//! Direct3D 12 Overlay Renderer using D3D11On12 interoperability layer.
//!
//! Provides seamless overlay presentation on Direct3D 12 swapchains by wrapping
//! swapchain backbuffers and executing the high-performance egui render pipeline.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use windows::core::{Interface, IUnknown, PCSTR};
use windows::Win32::Graphics::Direct3D::D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Direct3D11on12::*;
use windows::Win32::Graphics::Direct3D12::*;
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_R32G32_FLOAT, DXGI_FORMAT_R32_UINT, DXGI_FORMAT_R8G8B8A8_UNORM,
};
use windows::Win32::Graphics::Dxgi::{IDXGISwapChain, IDXGISwapChain3};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

type FnD3DCompile = unsafe extern "system" fn(
    *const c_void,
    usize,
    *const u8,
    *const c_void,
    *const c_void,
    *const u8,
    *const u8,
    u32,
    u32,
    *mut *mut c_void,
    *mut *mut c_void,
) -> i32;

type PfnD3D11On12CreateDevice = unsafe extern "system" fn(
    *mut c_void,        // pDevice (IUnknown* or ID3D12Device*)
    u32,                // Flags
    *const u32,         // pFeatureLevels
    u32,                // FeatureLevels
    *const *mut c_void, // ppCommandQueues
    u32,                // NumQueues
    u32,                // NodeMask
    *mut *mut c_void,   // ppDevice
    *mut *mut c_void,   // ppImmediateContext
    *mut u32,           // pChosenFeatureLevel
) -> i32;

struct TextureEntry {
    _texture: ID3D11Texture2D,
    srv: ID3D11ShaderResourceView,
    _width: u32,
    _height: u32,
}

struct WrappedBackBuffer {
    wrapped_resource: ID3D11Resource,
    rtv: ID3D11RenderTargetView,
}

struct D3D12RendererState {
    _d12_device: ID3D12Device,
    _command_queue: ID3D12CommandQueue,
    d11on12_device: ID3D11On12Device,
    d11_device: ID3D11Device,
    d11_context: ID3D11DeviceContext,
    wrapped_buffers: Vec<WrappedBackBuffer>,
    vertex_buffer: Option<ID3D11Buffer>,
    index_buffer: Option<ID3D11Buffer>,
    constant_buffer: Option<ID3D11Buffer>,
    vertex_buffer_cap: usize,
    index_buffer_cap: usize,
    vertex_shader: Option<ID3D11VertexShader>,
    pixel_shader: Option<ID3D11PixelShader>,
    input_layout: Option<ID3D11InputLayout>,
    blend_state: Option<ID3D11BlendState>,
    rasterizer_state: Option<ID3D11RasterizerState>,
    depth_stencil_state: Option<ID3D11DepthStencilState>,
    sampler_state: Option<ID3D11SamplerState>,
    textures: HashMap<egui::TextureId, TextureEntry>,
    screen_width: f32,
    screen_height: f32,
}

static D3D12_RENDERER: Mutex<Option<D3D12RendererState>> = Mutex::new(None);

const HLSL_SHADER: &[u8] = b"
cbuffer ProjectionMatrixBuffer : register(b0) {
    float4x4 ProjectionMatrix;
};
struct VS_INPUT {
    float2 pos : POSITION;
    float2 uv  : TEXCOORD0;
    float4 col : COLOR0;
};
struct PS_INPUT {
    float4 pos : SV_POSITION;
    float4 col : COLOR0;
    float2 uv  : TEXCOORD0;
};
PS_INPUT VS(VS_INPUT input) {
    PS_INPUT output;
    output.pos = mul(ProjectionMatrix, float4(input.pos.xy, 0.0f, 1.0f));
    output.col = input.col;
    output.uv  = input.uv;
    return output;
}
Texture2D fontTexture : register(t0);
SamplerState fontSampler : register(s0);
float4 PS(PS_INPUT input) : SV_Target {
    float4 texColor = fontTexture.Sample(fontSampler, input.uv);
    return input.col * texColor;
}
\0";

/// Check if swapchain is Direct3D 12 and render overlay frame if so.
/// Returns true if handled by D3D12, false if not a D3D12 swapchain.
pub unsafe fn try_render_d3d12_overlay(swapchain_ptr: *mut c_void) -> bool {
    if swapchain_ptr.is_null() {
        return false;
    }

    let sc: &IDXGISwapChain = std::mem::transmute(&swapchain_ptr);

    let mut lock = match D3D12_RENDERER.lock() {
        Ok(l) => l,
        Err(_) => return false,
    };

    if lock.is_none() {
        // Query CommandQueue or Device from SwapChain
        let (d12_device, cmd_queue) = if let Ok(queue) = sc.GetDevice::<ID3D12CommandQueue>() {
            let mut dev: Option<ID3D12Device> = None;
            if let Err(e) = queue.GetDevice(&mut dev) {
                tracing::debug!("Failed to get ID3D12Device from CommandQueue: {:?}", e);
                return false;
            }
            let dev = match dev {
                Some(d) => d,
                None => return false,
            };
            (dev, queue)
        } else if let Ok(dev) = sc.GetDevice::<ID3D12Device>() {
            // Need a command queue; try to create one if necessary
            let queue_desc = D3D12_COMMAND_QUEUE_DESC {
                Type: D3D12_COMMAND_LIST_TYPE_DIRECT,
                Priority: 0,
                Flags: D3D12_COMMAND_QUEUE_FLAG_NONE,
                NodeMask: 0,
            };
            let queue: ID3D12CommandQueue = match dev.CreateCommandQueue(&queue_desc) {
                Ok(q) => q,
                Err(e) => {
                    tracing::debug!("Failed to create D3D12 CommandQueue: {:?}", e);
                    return false;
                }
            };
            (dev, queue)
        } else {
            return false;
        };

        // Load D3D11On12CreateDevice
        let d3d11_mod = LoadLibraryA(b"d3d11.dll\0".as_ptr());
        if d3d11_mod.is_null() {
            tracing::warn!("Failed to load d3d11.dll for D3D11On12");
            return false;
        }

        let create_proc = GetProcAddress(d3d11_mod, b"D3D11On12CreateDevice\0".as_ptr());
        let create_fn: PfnD3D11On12CreateDevice = match create_proc {
            Some(p) => std::mem::transmute(p),
            None => {
                tracing::warn!("D3D11On12CreateDevice not found in d3d11.dll");
                return false;
            }
        };

        let mut d11_dev_ptr: *mut c_void = std::ptr::null_mut();
        let mut d11_ctx_ptr: *mut c_void = std::ptr::null_mut();
        let mut chosen_level = 0u32;

        let queue_unk: IUnknown = match cmd_queue.cast() {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("Failed to cast D3D12 command queue to IUnknown: {:?}", e);
                return false;
            }
        };
        let queue_raw: *mut c_void = std::mem::transmute_copy(&queue_unk);
        let queue_arr = [queue_raw];

        let dev_unk: IUnknown = match d12_device.cast() {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("Failed to cast D3D12 device to IUnknown: {:?}", e);
                return false;
            }
        };
        let dev_raw: *mut c_void = std::mem::transmute_copy(&dev_unk);

        let hr = create_fn(
            dev_raw,
            0,
            std::ptr::null(),
            0,
            queue_arr.as_ptr(),
            1,
            0,
            &mut d11_dev_ptr,
            &mut d11_ctx_ptr,
            &mut chosen_level,
        );

        if hr != 0 || d11_dev_ptr.is_null() || d11_ctx_ptr.is_null() {
            tracing::warn!("D3D11On12CreateDevice returned hr = 0x{:X}", hr);
            return false;
        }

        let d11_device: ID3D11Device = std::mem::transmute(d11_dev_ptr);
        let d11_context: ID3D11DeviceContext = std::mem::transmute(d11_ctx_ptr);
        let d11on12_device: ID3D11On12Device = match d11_device.cast() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Failed to cast ID3D11Device to ID3D11On12Device: {:?}", e);
                return false;
            }
        };

        // Query swap chain buffer count and size
        let desc = match sc.GetDesc() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Failed to get DXGI swap chain desc: {:?}", e);
                return false;
            }
        };

        let width = if desc.BufferDesc.Width > 0 { desc.BufferDesc.Width as f32 } else { 1280.0 };
        let height = if desc.BufferDesc.Height > 0 { desc.BufferDesc.Height as f32 } else { 800.0 };

        let buffer_count = desc.BufferCount.max(1);
        let mut wrapped_buffers = Vec::with_capacity(buffer_count as usize);

        for i in 0..buffer_count {
            let res_12: ID3D12Resource = match sc.GetBuffer(i) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Failed to get D3D12 swapchain buffer {}: {:?}", i, e);
                    break;
                }
            };

            let rflags = D3D11_RESOURCE_FLAGS {
                BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32,
                MiscFlags: 0,
                CPUAccessFlags: 0,
                StructureByteStride: 0,
            };

            let mut wrapped_res: Option<ID3D11Resource> = None;
            let hr_wrap = d11on12_device.CreateWrappedResource(
                &res_12,
                &rflags,
                D3D12_RESOURCE_STATE_PRESENT,
                D3D12_RESOURCE_STATE_PRESENT,
                &mut wrapped_res,
            );

            if hr_wrap.is_ok() && let Some(wrap) = wrapped_res {
                let mut rtv = None;
                if d11_device.CreateRenderTargetView(&wrap, None, Some(&mut rtv)).is_ok()
                    && let Some(rtv_view) = rtv
                {
                    wrapped_buffers.push(WrappedBackBuffer {
                        wrapped_resource: wrap,
                        rtv: rtv_view,
                    });
                }
            }
        }

        if wrapped_buffers.is_empty() {
            tracing::warn!("Could not wrap any D3D12 backbuffers for D3D11On12");
            return false;
        }

        tracing::info!(
            "Initialized D3D11On12 overlay renderer with {} wrapped buffers (res: {}x{})",
            wrapped_buffers.len(),
            width,
            height
        );

        *lock = Some(D3D12RendererState {
            _d12_device: d12_device,
            _command_queue: cmd_queue,
            d11on12_device,
            d11_device,
            d11_context,
            wrapped_buffers,
            vertex_buffer: None,
            index_buffer: None,
            constant_buffer: None,
            vertex_buffer_cap: 0,
            index_buffer_cap: 0,
            vertex_shader: None,
            pixel_shader: None,
            input_layout: None,
            blend_state: None,
            rasterizer_state: None,
            depth_stencil_state: None,
            sampler_state: None,
            textures: HashMap::new(),
            screen_width: width,
            screen_height: height,
        });
    }

    let state = match lock.as_mut() {
        Some(s) => s,
        None => return false,
    };

    // Determine current backbuffer index
    let backbuffer_idx = if let Ok(sc3) = sc.cast::<IDXGISwapChain3>() {
        sc3.GetCurrentBackBufferIndex() as usize
    } else {
        0
    };

    let target = if backbuffer_idx < state.wrapped_buffers.len() {
        &state.wrapped_buffers[backbuffer_idx]
    } else if !state.wrapped_buffers.is_empty() {
        &state.wrapped_buffers[0]
    } else {
        return false;
    };

    // Acquire wrapped backbuffer for D3D11 writing
    let res_opt = [Some(target.wrapped_resource.clone())];
    state.d11on12_device.AcquireWrappedResources(&res_opt);

    // Capture state guard
    let _state_guard = super::d3d11::D3D11StateBackup::capture(&state.d11_context);

    // Compile shaders if not present
    if state.vertex_shader.is_none() {
        let compiler_dll = LoadLibraryA(b"d3dcompiler_47.dll\0".as_ptr());
        let d3d_compile_ptr = if !compiler_dll.is_null() {
            GetProcAddress(compiler_dll, b"D3DCompile\0".as_ptr())
        } else {
            None
        };

        if let Some(compile_proc) = d3d_compile_ptr {
            let d3d_compile: FnD3DCompile = std::mem::transmute(compile_proc);
            let mut vs_blob: *mut c_void = std::ptr::null_mut();
            let mut ps_blob: *mut c_void = std::ptr::null_mut();
            let mut err_blob: *mut c_void = std::ptr::null_mut();

            let hr_vs = d3d_compile(
                HLSL_SHADER.as_ptr() as *const c_void,
                HLSL_SHADER.len(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                b"VS\0".as_ptr(),
                b"vs_4_0\0".as_ptr(),
                0,
                0,
                &mut vs_blob,
                &mut err_blob,
            );

            let hr_ps = d3d_compile(
                HLSL_SHADER.as_ptr() as *const c_void,
                HLSL_SHADER.len(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                b"PS\0".as_ptr(),
                b"ps_4_0\0".as_ptr(),
                0,
                0,
                &mut ps_blob,
                &mut err_blob,
            );

            if hr_vs == 0 && hr_ps == 0 && !vs_blob.is_null() && !ps_blob.is_null() {
                let vs_vt = *(vs_blob as *mut *mut usize);
                let get_vs_buf: unsafe extern "system" fn(*mut c_void) -> *const c_void =
                    std::mem::transmute(*vs_vt.add(3));
                let get_vs_size: unsafe extern "system" fn(*mut c_void) -> usize =
                    std::mem::transmute(*vs_vt.add(4));
                let vs_bytecode = std::slice::from_raw_parts(get_vs_buf(vs_blob) as *const u8, get_vs_size(vs_blob));

                let ps_vt = *(ps_blob as *mut *mut usize);
                let get_ps_buf: unsafe extern "system" fn(*mut c_void) -> *const c_void =
                    std::mem::transmute(*ps_vt.add(3));
                let get_ps_size: unsafe extern "system" fn(*mut c_void) -> usize =
                    std::mem::transmute(*ps_vt.add(4));
                let ps_bytecode = std::slice::from_raw_parts(get_ps_buf(ps_blob) as *const u8, get_ps_size(ps_blob));

                let mut vs = None;
                if state.d11_device.CreateVertexShader(vs_bytecode, None, Some(&mut vs)).is_ok() {
                    state.vertex_shader = vs;
                }

                let mut ps = None;
                if state.d11_device.CreatePixelShader(ps_bytecode, None, Some(&mut ps)).is_ok() {
                    state.pixel_shader = ps;
                }

                let input_elements = [
                    D3D11_INPUT_ELEMENT_DESC {
                        SemanticName: PCSTR(b"POSITION\0".as_ptr()),
                        SemanticIndex: 0,
                        Format: DXGI_FORMAT_R32G32_FLOAT,
                        InputSlot: 0,
                        AlignedByteOffset: 0,
                        InputSlotClass: D3D11_INPUT_PER_VERTEX_DATA,
                        InstanceDataStepRate: 0,
                    },
                    D3D11_INPUT_ELEMENT_DESC {
                        SemanticName: PCSTR(b"TEXCOORD\0".as_ptr()),
                        SemanticIndex: 0,
                        Format: DXGI_FORMAT_R32G32_FLOAT,
                        InputSlot: 0,
                        AlignedByteOffset: 8,
                        InputSlotClass: D3D11_INPUT_PER_VERTEX_DATA,
                        InstanceDataStepRate: 0,
                    },
                    D3D11_INPUT_ELEMENT_DESC {
                        SemanticName: PCSTR(b"COLOR\0".as_ptr()),
                        SemanticIndex: 0,
                        Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                        InputSlot: 0,
                        AlignedByteOffset: 16,
                        InputSlotClass: D3D11_INPUT_PER_VERTEX_DATA,
                        InstanceDataStepRate: 0,
                    },
                ];

                let mut il = None;
                if state.d11_device.CreateInputLayout(&input_elements, vs_bytecode, Some(&mut il)).is_ok() {
                    state.input_layout = il;
                }

                let rel_vs: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(*vs_vt.add(2));
                let rel_ps: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(*ps_vt.add(2));
                rel_vs(vs_blob);
                rel_ps(ps_blob);
            }
        }
    }

    // Projection Constant Buffer
    if state.constant_buffer.is_none() {
        let cb_desc = D3D11_BUFFER_DESC {
            ByteWidth: 64,
            Usage: D3D11_USAGE_DYNAMIC,
            BindFlags: D3D11_BIND_CONSTANT_BUFFER.0 as u32,
            CPUAccessFlags: D3D11_CPU_ACCESS_WRITE.0 as u32,
            MiscFlags: 0,
            StructureByteStride: 0,
        };
        let mut cb = None;
        if state.d11_device.CreateBuffer(&cb_desc, None, Some(&mut cb)).is_ok() {
            state.constant_buffer = cb;
        }
    }

    let w = state.screen_width;
    let h = state.screen_height;
    if let Some(cb) = state.constant_buffer.as_ref() {
        let l = 0.0f32;
        let r = w;
        let t = 0.0f32;
        let b = h;
        let proj_matrix: [f32; 16] = [
            2.0 / (r - l), 0.0,           0.0, 0.0,
            0.0,           2.0 / (t - b), 0.0, 0.0,
            0.0,           0.0,           0.5, 0.0,
            (r + l) / (l - r), (t + b) / (b - t), 0.5, 1.0,
        ];

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        if state.d11_context.Map(cb, 0, D3D11_MAP_WRITE_DISCARD, 0, Some(&mut mapped)).is_ok() {
            std::ptr::copy_nonoverlapping(proj_matrix.as_ptr() as *const c_void, mapped.pData, 64);
            state.d11_context.Unmap(cb, 0);
        }
    }

    // Pipeline States
    if state.blend_state.is_none() {
        let mut blend_desc = D3D11_BLEND_DESC::default();
        blend_desc.RenderTarget[0] = D3D11_RENDER_TARGET_BLEND_DESC {
            BlendEnable: true.into(),
            SrcBlend: D3D11_BLEND_SRC_ALPHA,
            DestBlend: D3D11_BLEND_INV_SRC_ALPHA,
            BlendOp: D3D11_BLEND_OP_ADD,
            SrcBlendAlpha: D3D11_BLEND_ONE,
            DestBlendAlpha: D3D11_BLEND_INV_SRC_ALPHA,
            BlendOpAlpha: D3D11_BLEND_OP_ADD,
            RenderTargetWriteMask: D3D11_COLOR_WRITE_ENABLE_ALL.0 as u8,
        };
        let mut bs = None;
        if state.d11_device.CreateBlendState(&blend_desc, Some(&mut bs)).is_ok() {
            state.blend_state = bs;
        }
    }

    if state.rasterizer_state.is_none() {
        let rast_desc = D3D11_RASTERIZER_DESC {
            FillMode: D3D11_FILL_SOLID,
            CullMode: D3D11_CULL_NONE,
            ScissorEnable: false.into(),
            DepthClipEnable: true.into(),
            ..Default::default()
        };
        let mut rs = None;
        if state.d11_device.CreateRasterizerState(&rast_desc, Some(&mut rs)).is_ok() {
            state.rasterizer_state = rs;
        }
    }

    if state.depth_stencil_state.is_none() {
        let mut ds_desc = D3D11_DEPTH_STENCIL_DESC::default();
        ds_desc.DepthEnable = false.into();
        let mut ds = None;
        if state.d11_device.CreateDepthStencilState(&ds_desc, Some(&mut ds)).is_ok() {
            state.depth_stencil_state = ds;
        }
    }

    if state.sampler_state.is_none() {
        let sampler_desc = D3D11_SAMPLER_DESC {
            Filter: D3D11_FILTER_MIN_MAG_MIP_LINEAR,
            AddressU: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressV: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressW: D3D11_TEXTURE_ADDRESS_CLAMP,
            MaxAnisotropy: 1,
            MinLOD: 0.0,
            MaxLOD: f32::MAX,
            ..Default::default()
        };
        let mut ss = None;
        if state.d11_device.CreateSamplerState(&sampler_desc, Some(&mut ss)).is_ok() {
            state.sampler_state = ss;
        }
    }

    // Bind Render Targets and Pipeline
    let rtv_opt = [Some(target.rtv.clone())];
    state.d11_context.OMSetRenderTargets(Some(&rtv_opt), None);

    let vp = [D3D11_VIEWPORT {
        TopLeftX: 0.0,
        TopLeftY: 0.0,
        Width: w,
        Height: h,
        MinDepth: 0.0,
        MaxDepth: 1.0,
    }];
    state.d11_context.RSSetViewports(Some(&vp));

    if let Some(bs) = state.blend_state.as_ref() {
        state.d11_context.OMSetBlendState(bs, Some(&[0.0; 4]), 0xFFFFFFFF);
    }
    if let Some(rs) = state.rasterizer_state.as_ref() {
        state.d11_context.RSSetState(rs);
    }
    if let Some(ds) = state.depth_stencil_state.as_ref() {
        state.d11_context.OMSetDepthStencilState(ds, 0);
    }
    if let Some(vs) = state.vertex_shader.as_ref() {
        state.d11_context.VSSetShader(vs, None);
    }
    if let Some(ps) = state.pixel_shader.as_ref() {
        state.d11_context.PSSetShader(ps, None);
    }
    if let Some(il) = state.input_layout.as_ref() {
        state.d11_context.IASetInputLayout(il);
    }
    if let Some(cb) = state.constant_buffer.as_ref() {
        let cb_opt = [Some(cb.clone())];
        state.d11_context.VSSetConstantBuffers(0, Some(&cb_opt));
    }
    if let Some(ss) = state.sampler_state.as_ref() {
        let ss_opt = [Some(ss.clone())];
        state.d11_context.PSSetSamplers(0, Some(&ss_opt));
    }

    // Run egui
    if let Some((_egui_ctx, clipped_primitives, textures_delta)) =
        super::overlay::render_in_game_egui(w, h)
    {
        for id in &textures_delta.free {
            state.textures.remove(id);
        }

        for (id, delta) in &textures_delta.set {
            let (pixels_rgba, tex_w, tex_h) = match &delta.image {
                egui::ImageData::Color(c) => {
                    let rgba: Vec<u8> = c.pixels.iter().flat_map(|p| p.to_array()).collect();
                    (rgba, c.width() as u32, c.height() as u32)
                }
                egui::ImageData::Font(f) => {
                    let rgba: Vec<u8> = f
                        .srgba_pixels(None)
                        .flat_map(|p| p.to_array())
                        .collect();
                    (rgba, f.width() as u32, f.height() as u32)
                }
            };

            if let Some(pos) = delta.pos {
                if let Some(entry) = state.textures.get_mut(id) {
                    let box_3d = D3D11_BOX {
                        left: pos[0] as u32,
                        top: pos[1] as u32,
                        front: 0,
                        right: (pos[0] as u32) + tex_w,
                        bottom: (pos[1] as u32) + tex_h,
                        back: 1,
                    };
                    state.d11_context.UpdateSubresource(
                        &entry._texture,
                        0,
                        Some(&box_3d),
                        pixels_rgba.as_ptr() as *const c_void,
                        tex_w * 4,
                        0,
                    );
                }
            } else {
                let tex_desc = D3D11_TEXTURE2D_DESC {
                    Width: tex_w,
                    Height: tex_h,
                    MipLevels: 1,
                    ArraySize: 1,
                    Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                    SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                        Count: 1,
                        Quality: 0,
                    },
                    Usage: D3D11_USAGE_DEFAULT,
                    BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                    CPUAccessFlags: 0,
                    MiscFlags: 0,
                };

                let subresource = D3D11_SUBRESOURCE_DATA {
                    pSysMem: pixels_rgba.as_ptr() as *const c_void,
                    SysMemPitch: tex_w * 4,
                    SysMemSlicePitch: 0,
                };

                let mut texture = None;
                if state.d11_device.CreateTexture2D(&tex_desc, Some(&subresource), Some(&mut texture)).is_ok()
                    && let Some(tex) = texture
                {
                    let mut srv = None;
                    if state.d11_device.CreateShaderResourceView(&tex, None, Some(&mut srv)).is_ok()
                        && let Some(srv_view) = srv
                    {
                        state.textures.insert(
                            *id,
                            TextureEntry {
                                _texture: tex,
                                srv: srv_view,
                                _width: tex_w,
                                _height: tex_h,
                            },
                        );
                    }
                }
            }
        }

        for clipped_primitive in clipped_primitives {
            if let egui::epaint::Primitive::Mesh(mesh) = clipped_primitive.primitive {
                if mesh.indices.is_empty() || mesh.vertices.is_empty() {
                    continue;
                }

                if let Some(entry) = state.textures.get(&mesh.texture_id) {
                    let srv_opt = [Some(entry.srv.clone())];
                    state.d11_context.PSSetShaderResources(0, Some(&srv_opt));
                }

                let vb_byte_size = mesh.vertices.len() * std::mem::size_of::<egui::epaint::Vertex>();
                let ib_byte_size = mesh.indices.len() * std::mem::size_of::<u32>();

                if state.vertex_buffer.is_none() || state.vertex_buffer_cap < vb_byte_size {
                    let vb_desc = D3D11_BUFFER_DESC {
                        ByteWidth: (vb_byte_size.max(65536)) as u32,
                        Usage: D3D11_USAGE_DYNAMIC,
                        BindFlags: D3D11_BIND_VERTEX_BUFFER.0 as u32,
                        CPUAccessFlags: D3D11_CPU_ACCESS_WRITE.0 as u32,
                        MiscFlags: 0,
                        StructureByteStride: 0,
                    };
                    let mut vb = None;
                    if state.d11_device.CreateBuffer(&vb_desc, None, Some(&mut vb)).is_ok() {
                        state.vertex_buffer = vb;
                        state.vertex_buffer_cap = vb_desc.ByteWidth as usize;
                    }
                }

                if state.index_buffer.is_none() || state.index_buffer_cap < ib_byte_size {
                    let ib_desc = D3D11_BUFFER_DESC {
                        ByteWidth: (ib_byte_size.max(65536)) as u32,
                        Usage: D3D11_USAGE_DYNAMIC,
                        BindFlags: D3D11_BIND_INDEX_BUFFER.0 as u32,
                        CPUAccessFlags: D3D11_CPU_ACCESS_WRITE.0 as u32,
                        MiscFlags: 0,
                        StructureByteStride: 0,
                    };
                    let mut ib = None;
                    if state.d11_device.CreateBuffer(&ib_desc, None, Some(&mut ib)).is_ok() {
                        state.index_buffer = ib;
                        state.index_buffer_cap = ib_desc.ByteWidth as usize;
                    }
                }

                if let Some(vb) = state.vertex_buffer.as_ref() {
                    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                    if state.d11_context.Map(vb, 0, D3D11_MAP_WRITE_DISCARD, 0, Some(&mut mapped)).is_ok() {
                        std::ptr::copy_nonoverlapping(
                            mesh.vertices.as_ptr() as *const c_void,
                            mapped.pData,
                            vb_byte_size,
                        );
                        state.d11_context.Unmap(vb, 0);
                    }
                }

                if let Some(ib) = state.index_buffer.as_ref() {
                    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                    if state.d11_context.Map(ib, 0, D3D11_MAP_WRITE_DISCARD, 0, Some(&mut mapped)).is_ok() {
                        std::ptr::copy_nonoverlapping(
                            mesh.indices.as_ptr() as *const c_void,
                            mapped.pData,
                            ib_byte_size,
                        );
                        state.d11_context.Unmap(ib, 0);
                    }
                }

                if let (Some(vb), Some(ib)) = (state.vertex_buffer.as_ref(), state.index_buffer.as_ref()) {
                    let stride = [std::mem::size_of::<egui::epaint::Vertex>() as u32];
                    let offset = [0u32];
                    let vb_opt = [Some(vb.clone())];
                    state.d11_context.IASetVertexBuffers(0, 1, Some(vb_opt.as_ptr()), Some(stride.as_ptr()), Some(offset.as_ptr()));
                    state.d11_context.IASetIndexBuffer(ib, DXGI_FORMAT_R32_UINT, 0);
                    state.d11_context.IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
                    state.d11_context.DrawIndexed(mesh.indices.len() as u32, 0, 0);
                }
            }
        }
    }

    // Release wrapped backbuffer to transition back to D3D12 presentation
    state.d11on12_device.ReleaseWrappedResources(&res_opt);
    state.d11_context.Flush();

    true
}
