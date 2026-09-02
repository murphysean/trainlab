//! Native Direct3D 11 backend renderer for `egui 0.27` using official Microsoft DirectX COM bindings.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use windows::core::PCSTR;
use windows::Win32::Graphics::Direct3D::{D3D_PRIMITIVE_TOPOLOGY, D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST};
use windows::Win32::Graphics::Direct3D11::{
    ID3D11BlendState, ID3D11Buffer, ID3D11DepthStencilState, ID3D11DepthStencilView, ID3D11Device, ID3D11DeviceContext,
    ID3D11InputLayout, ID3D11PixelShader, ID3D11RasterizerState, ID3D11RenderTargetView,
    ID3D11SamplerState, ID3D11ShaderResourceView, ID3D11Texture2D, ID3D11VertexShader,
    D3D11_BIND_CONSTANT_BUFFER, D3D11_BIND_INDEX_BUFFER, D3D11_BIND_SHADER_RESOURCE,
    D3D11_BIND_VERTEX_BUFFER, D3D11_BLEND_DESC, D3D11_BLEND_INV_SRC_ALPHA, D3D11_BLEND_ONE,
    D3D11_BLEND_OP_ADD, D3D11_BLEND_SRC_ALPHA, D3D11_BUFFER_DESC, D3D11_COLOR_WRITE_ENABLE_ALL,
    D3D11_CPU_ACCESS_WRITE, D3D11_CULL_NONE, D3D11_DEPTH_STENCIL_DESC, D3D11_FILL_SOLID,
    D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_INPUT_PER_VERTEX_DATA, D3D11_INPUT_ELEMENT_DESC,
    D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_WRITE_DISCARD, D3D11_RASTERIZER_DESC,
    D3D11_RENDER_TARGET_BLEND_DESC, D3D11_SAMPLER_DESC, D3D11_SUBRESOURCE_DATA,
    D3D11_TEXTURE2D_DESC, D3D11_TEXTURE_ADDRESS_CLAMP, D3D11_USAGE_DEFAULT, D3D11_USAGE_DYNAMIC,
    D3D11_VIEWPORT,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT, DXGI_FORMAT_R32G32_FLOAT, DXGI_FORMAT_R32_UINT, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_FORMAT_UNKNOWN,
};
use windows::Win32::Graphics::Dxgi::IDXGISwapChain;
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

struct TextureEntry {
    _texture: ID3D11Texture2D,
    srv: ID3D11ShaderResourceView,
    _width: u32,
    _height: u32,
}

struct RendererState {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    rtv: Option<ID3D11RenderTargetView>,
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
}

static RENDERER: Mutex<Option<RendererState>> = Mutex::new(None);

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

/// RAII guard that captures and restores Direct3D 11 pipeline state across overlay drawing.
pub struct D3D11StateBackup<'a> {
    context: &'a ID3D11DeviceContext,
    rtv: [Option<ID3D11RenderTargetView>; 1],
    dsv: Option<ID3D11DepthStencilView>,
    num_viewports: u32,
    viewports: [D3D11_VIEWPORT; 1],
    blend_state: Option<ID3D11BlendState>,
    blend_factor: [f32; 4],
    sample_mask: u32,
    rasterizer_state: Option<ID3D11RasterizerState>,
    depth_stencil_state: Option<ID3D11DepthStencilState>,
    stencil_ref: u32,
    input_layout: Option<ID3D11InputLayout>,
    topology: D3D_PRIMITIVE_TOPOLOGY,
    vertex_buffer: [Option<ID3D11Buffer>; 1],
    vb_stride: [u32; 1],
    vb_offset: [u32; 1],
    index_buffer: Option<ID3D11Buffer>,
    ib_format: DXGI_FORMAT,
    ib_offset: u32,
    vertex_shader: Option<ID3D11VertexShader>,
    pixel_shader: Option<ID3D11PixelShader>,
    vs_constant_buffer: [Option<ID3D11Buffer>; 1],
    ps_sampler: [Option<ID3D11SamplerState>; 1],
    ps_srv: [Option<ID3D11ShaderResourceView>; 1],
}

impl<'a> D3D11StateBackup<'a> {
    pub unsafe fn capture(context: &'a ID3D11DeviceContext) -> Self {
        let mut rtv: [Option<ID3D11RenderTargetView>; 1] = [None];
        let mut dsv: Option<ID3D11DepthStencilView> = None;
        unsafe { context.OMGetRenderTargets(Some(&mut rtv), Some(&mut dsv)) };

        let mut num_viewports = 1u32;
        let mut viewports = [D3D11_VIEWPORT::default()];
        unsafe { context.RSGetViewports(&mut num_viewports, Some(viewports.as_mut_ptr())) };

        let mut blend_state = None;
        let mut blend_factor = [0.0f32; 4];
        let mut sample_mask = 0u32;
        unsafe { context.OMGetBlendState(Some(&mut blend_state), Some(&mut blend_factor), Some(&mut sample_mask)) };

        let rasterizer_state = unsafe { context.RSGetState().ok() };

        let mut depth_stencil_state = None;
        let mut stencil_ref = 0u32;
        unsafe { context.OMGetDepthStencilState(Some(&mut depth_stencil_state), Some(&mut stencil_ref)) };

        let input_layout = unsafe { context.IAGetInputLayout().ok() };
        let topology = unsafe { context.IAGetPrimitiveTopology() };

        let mut vertex_buffer: [Option<ID3D11Buffer>; 1] = [None];
        let mut vb_stride = [0u32];
        let mut vb_offset = [0u32];
        unsafe {
            context.IAGetVertexBuffers(
                0,
                1,
                Some(vertex_buffer.as_mut_ptr()),
                Some(vb_stride.as_mut_ptr()),
                Some(vb_offset.as_mut_ptr()),
            )
        };

        let mut index_buffer = None;
        let mut ib_format = DXGI_FORMAT_UNKNOWN;
        let mut ib_offset = 0u32;
        unsafe { context.IAGetIndexBuffer(Some(&mut index_buffer), Some(&mut ib_format), Some(&mut ib_offset)) };

        let mut vertex_shader = None;
        unsafe { context.VSGetShader(&mut vertex_shader, None, None) };

        let mut pixel_shader = None;
        unsafe { context.PSGetShader(&mut pixel_shader, None, None) };

        let mut vs_constant_buffer: [Option<ID3D11Buffer>; 1] = [None];
        unsafe { context.VSGetConstantBuffers(0, Some(&mut vs_constant_buffer)) };

        let mut ps_sampler: [Option<ID3D11SamplerState>; 1] = [None];
        unsafe { context.PSGetSamplers(0, Some(&mut ps_sampler)) };

        let mut ps_srv: [Option<ID3D11ShaderResourceView>; 1] = [None];
        unsafe { context.PSGetShaderResources(0, Some(&mut ps_srv)) };

        Self {
            context,
            rtv,
            dsv,
            num_viewports,
            viewports,
            blend_state,
            blend_factor,
            sample_mask,
            rasterizer_state,
            depth_stencil_state,
            stencil_ref,
            input_layout,
            topology,
            vertex_buffer,
            vb_stride,
            vb_offset,
            index_buffer,
            ib_format,
            ib_offset,
            vertex_shader,
            pixel_shader,
            vs_constant_buffer,
            ps_sampler,
            ps_srv,
        }
    }

    pub unsafe fn restore(&self) {
        unsafe {
            self.context.OMSetRenderTargets(Some(&self.rtv), self.dsv.as_ref());
            if self.num_viewports > 0 {
                self.context.RSSetViewports(Some(&self.viewports[..self.num_viewports as usize]));
            }
            self.context.OMSetBlendState(self.blend_state.as_ref(), Some(&self.blend_factor), self.sample_mask);
            self.context.RSSetState(self.rasterizer_state.as_ref());
            self.context.OMSetDepthStencilState(self.depth_stencil_state.as_ref(), self.stencil_ref);
            self.context.IASetInputLayout(self.input_layout.as_ref());
            self.context.IASetPrimitiveTopology(self.topology);

            let vb_ptrs: [Option<ID3D11Buffer>; 1] = [self.vertex_buffer[0].clone()];
            self.context.IASetVertexBuffers(0, 1, Some(vb_ptrs.as_ptr()), Some(self.vb_stride.as_ptr()), Some(self.vb_offset.as_ptr()));
            self.context.IASetIndexBuffer(self.index_buffer.as_ref(), self.ib_format, self.ib_offset);

            self.context.VSSetShader(self.vertex_shader.as_ref(), None);
            self.context.PSSetShader(self.pixel_shader.as_ref(), None);
            self.context.VSSetConstantBuffers(0, Some(&self.vs_constant_buffer));
            self.context.PSSetSamplers(0, Some(&self.ps_sampler));
            self.context.PSSetShaderResources(0, Some(&self.ps_srv));
        }
    }
}

impl<'a> Drop for D3D11StateBackup<'a> {
    fn drop(&mut self) {
        unsafe { self.restore(); }
    }
}

/// Render in-game cheat overlay directly onto the active swapchain backbuffer.
pub unsafe fn render_overlay_frame(swapchain_ptr: *mut c_void) {
    if swapchain_ptr.is_null() {
        return;
    }

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut lock = match RENDERER.lock() {
            Ok(l) => l,
            Err(_) => return,
        };

        if lock.is_none() {
            let sc: &IDXGISwapChain = unsafe { std::mem::transmute(&swapchain_ptr) };

            let device: ID3D11Device = match unsafe { sc.GetDevice() } {
                Ok(d) => d,
                Err(_) => return,
            };

            let context: ID3D11DeviceContext = match unsafe { device.GetImmediateContext() } {
                Ok(ctx) => ctx,
                Err(_) => return,
            };

            *lock = Some(RendererState {
                device,
                context,
                rtv: None,
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
            });
        }

        let state = match lock.as_mut() {
            Some(s) => s,
            None => return,
        };

        // Capture Game Pipeline State before applying overlay render pipeline states
        let _state_guard = unsafe { D3D11StateBackup::capture(&state.context) };

        // 1. Resolve Backbuffer Render Target View
        if state.rtv.is_none() {
            let sc: &IDXGISwapChain = unsafe { std::mem::transmute(&swapchain_ptr) };
            if let Ok(backbuffer) = unsafe { sc.GetBuffer::<ID3D11Texture2D>(0) } {
                let mut rtv = None;
                if (unsafe { state.device.CreateRenderTargetView(&backbuffer, None, Some(&mut rtv)) }).is_ok() {
                    state.rtv = rtv;
                }
            }
        }

        let rtv = match state.rtv.as_ref() {
            Some(r) => r,
            None => return,
        };

        // 2. Compile and Initialize Shaders and Input Layout on First Run
        if state.vertex_shader.is_none() {
            let compiler_dll = unsafe { LoadLibraryA(b"d3dcompiler_47.dll\0".as_ptr()) };
            let d3d_compile_ptr = if compiler_dll != std::ptr::null_mut() {
                unsafe { GetProcAddress(compiler_dll, b"D3DCompile\0".as_ptr()) }
            } else {
                None
            };

            if let Some(compile_proc) = d3d_compile_ptr {
                let d3d_compile: FnD3DCompile = unsafe { std::mem::transmute(compile_proc) };
                let mut vs_blob: *mut c_void = std::ptr::null_mut();
                let mut ps_blob: *mut c_void = std::ptr::null_mut();
                let mut err_blob: *mut c_void = std::ptr::null_mut();

                // Compile VS
                let hr_vs = unsafe {
                    d3d_compile(
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
                    )
                };

                // Compile PS
                let hr_ps = unsafe {
                    d3d_compile(
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
                    )
                };

                if hr_vs == 0 && hr_ps == 0 && !vs_blob.is_null() && !ps_blob.is_null() {
                    let vs_vt = unsafe { *(vs_blob as *mut *mut usize) };
                    let get_vs_buf: unsafe extern "system" fn(*mut c_void) -> *const c_void =
                        unsafe { std::mem::transmute(*vs_vt.add(3)) };
                    let get_vs_size: unsafe extern "system" fn(*mut c_void) -> usize =
                        unsafe { std::mem::transmute(*vs_vt.add(4)) };
                    let vs_bytecode = unsafe { std::slice::from_raw_parts(get_vs_buf(vs_blob) as *const u8, get_vs_size(vs_blob)) };

                    let ps_vt = unsafe { *(ps_blob as *mut *mut usize) };
                    let get_ps_buf: unsafe extern "system" fn(*mut c_void) -> *const c_void =
                        unsafe { std::mem::transmute(*ps_vt.add(3)) };
                    let get_ps_size: unsafe extern "system" fn(*mut c_void) -> usize =
                        unsafe { std::mem::transmute(*ps_vt.add(4)) };
                    let ps_bytecode = unsafe { std::slice::from_raw_parts(get_ps_buf(ps_blob) as *const u8, get_ps_size(ps_blob)) };

                    let mut vs = None;
                    if (unsafe { state.device.CreateVertexShader(vs_bytecode, None, Some(&mut vs)) }).is_ok() {
                        state.vertex_shader = vs;
                    }

                    let mut ps = None;
                    if (unsafe { state.device.CreatePixelShader(ps_bytecode, None, Some(&mut ps)) }).is_ok() {
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
                    if (unsafe { state.device.CreateInputLayout(&input_elements, vs_bytecode, Some(&mut il)) }).is_ok() {
                        state.input_layout = il;
                    }

                    let rel_vs: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(*vs_vt.add(2)) };
                    let rel_ps: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(*ps_vt.add(2)) };
                    unsafe {
                        rel_vs(vs_blob);
                        rel_ps(ps_blob);
                    }
                }
            }
        }

        // 3. Create Projection Constant Buffer
        if state.constant_buffer.is_none() {
            let cb_desc = D3D11_BUFFER_DESC {
                ByteWidth: 64, // sizeof(float4x4) = 64 bytes
                Usage: D3D11_USAGE_DYNAMIC,
                BindFlags: D3D11_BIND_CONSTANT_BUFFER.0 as u32,
                CPUAccessFlags: D3D11_CPU_ACCESS_WRITE.0 as u32,
                MiscFlags: 0,
                StructureByteStride: 0,
            };
            let mut cb = None;
            if (unsafe { state.device.CreateBuffer(&cb_desc, None, Some(&mut cb)) }).is_ok() {
                state.constant_buffer = cb;
            }
        }

        // Update Projection Matrix (Screen 1280x800 to NDC [-1, 1])
        if let Some(cb) = state.constant_buffer.as_ref() {
            let l = 0.0f32;
            let r = 1280.0f32;
            let t = 0.0f32;
            let b = 800.0f32;
            let proj_matrix: [f32; 16] = [
                2.0 / (r - l), 0.0,           0.0, 0.0,
                0.0,           2.0 / (t - b), 0.0, 0.0,
                0.0,           0.0,           0.5, 0.0,
                (r + l) / (l - r), (t + b) / (b - t), 0.5, 1.0,
            ];

            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            if (unsafe { state.context.Map(cb, 0, D3D11_MAP_WRITE_DISCARD, 0, Some(&mut mapped)) }).is_ok() {
                unsafe {
                    std::ptr::copy_nonoverlapping(proj_matrix.as_ptr() as *const c_void, mapped.pData, 64);
                    state.context.Unmap(cb, 0);
                }
            }
        }

        // 4. Initialize State Objects (Blend, Rasterizer, DepthStencil, Sampler)
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
            if (unsafe { state.device.CreateBlendState(&blend_desc, Some(&mut bs)) }).is_ok() {
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
            if (unsafe { state.device.CreateRasterizerState(&rast_desc, Some(&mut rs)) }).is_ok() {
                state.rasterizer_state = rs;
            }
        }

        if state.depth_stencil_state.is_none() {
            let mut ds_desc = D3D11_DEPTH_STENCIL_DESC::default();
            ds_desc.DepthEnable = false.into();
            let mut ds = None;
            if (unsafe { state.device.CreateDepthStencilState(&ds_desc, Some(&mut ds)) }).is_ok() {
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
            if (unsafe { state.device.CreateSamplerState(&sampler_desc, Some(&mut ss)) }).is_ok() {
                state.sampler_state = ss;
            }
        }

        // 5. Bind Pipeline States
        let rtv_opt = [Some(rtv.clone())];
        unsafe {
            state.context.OMSetRenderTargets(Some(&rtv_opt), None);

            let vp = [D3D11_VIEWPORT {
                TopLeftX: 0.0,
                TopLeftY: 0.0,
                Width: 1280.0,
                Height: 800.0,
                MinDepth: 0.0,
                MaxDepth: 1.0,
            }];
            state.context.RSSetViewports(Some(&vp));

            if let Some(bs) = state.blend_state.as_ref() {
                state.context.OMSetBlendState(bs, Some(&[0.0; 4]), 0xFFFFFFFF);
            }
            if let Some(rs) = state.rasterizer_state.as_ref() {
                state.context.RSSetState(rs);
            }
            if let Some(ds) = state.depth_stencil_state.as_ref() {
                state.context.OMSetDepthStencilState(ds, 0);
            }
            if let Some(vs) = state.vertex_shader.as_ref() {
                state.context.VSSetShader(vs, None);
            }
            if let Some(ps) = state.pixel_shader.as_ref() {
                state.context.PSSetShader(ps, None);
            }
            if let Some(il) = state.input_layout.as_ref() {
                state.context.IASetInputLayout(il);
            }
            if let Some(cb) = state.constant_buffer.as_ref() {
                let cb_opt = [Some(cb.clone())];
                state.context.VSSetConstantBuffers(0, Some(&cb_opt));
            }
            if let Some(ss) = state.sampler_state.as_ref() {
                let ss_opt = [Some(ss.clone())];
                state.context.PSSetSamplers(0, Some(&ss_opt));
            }
        }

        // 6. Run egui Layout and Draw Primitives
        if let Some((_egui_ctx, clipped_primitives, textures_delta)) =
            super::overlay::render_in_game_egui(1280.0, 800.0)
        {
            // 6a. Delete freed textures
            for id in &textures_delta.free {
                state.textures.remove(id);
            }

            // 6b. Upload new / updated textures (with full sub-region and full-image update support)
            for (id, delta) in &textures_delta.set {
                let (pixels_rgba, width, height) = match &delta.image {
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
                    // Partial atlas texture sub-region update
                    if let Some(entry) = state.textures.get_mut(id) {
                        let box_3d = windows::Win32::Graphics::Direct3D11::D3D11_BOX {
                            left: pos[0] as u32,
                            top: pos[1] as u32,
                            front: 0,
                            right: (pos[0] as u32) + width,
                            bottom: (pos[1] as u32) + height,
                            back: 1,
                        };
                        unsafe {
                            state.context.UpdateSubresource(
                                &entry._texture,
                                0,
                                Some(&box_3d),
                                pixels_rgba.as_ptr() as *const c_void,
                                width * 4,
                                0,
                            );
                        }
                    }
                } else {
                    // Full texture creation
                    let tex_desc = D3D11_TEXTURE2D_DESC {
                        Width: width,
                        Height: height,
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
                        SysMemPitch: width * 4,
                        SysMemSlicePitch: 0,
                    };

                    let mut texture = None;
                    if (unsafe { state.device.CreateTexture2D(&tex_desc, Some(&subresource), Some(&mut texture)) }).is_ok()
                        && let Some(tex) = texture
                    {
                        let mut srv = None;
                        if (unsafe { state.device.CreateShaderResourceView(&tex, None, Some(&mut srv)) }).is_ok()
                            && let Some(srv_view) = srv
                        {
                            state.textures.insert(
                                *id,
                                TextureEntry {
                                    _texture: tex,
                                    srv: srv_view,
                                    _width: width,
                                    _height: height,
                                },
                            );
                        }
                    }
                }
            }

            // 7. Render Meshes with proper per-mesh texture binding
            for clipped_primitive in clipped_primitives {
                if let egui::epaint::Primitive::Mesh(mesh) = clipped_primitive.primitive {
                    if mesh.indices.is_empty() || mesh.vertices.is_empty() {
                        continue;
                    }

                    // Bind matching texture for this mesh (e.g. font atlas or custom texture)
                    if let Some(entry) = state.textures.get(&mesh.texture_id) {
                        let srv_opt = [Some(entry.srv.clone())];
                        unsafe { state.context.PSSetShaderResources(0, Some(&srv_opt)) };
                    }

                    let vb_byte_size = mesh.vertices.len() * std::mem::size_of::<egui::epaint::Vertex>();
                    let ib_byte_size = mesh.indices.len() * std::mem::size_of::<u32>();

                    // Create / Reallocate dynamic Vertex Buffer
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
                        if (unsafe { state.device.CreateBuffer(&vb_desc, None, Some(&mut vb)) }).is_ok() {
                            state.vertex_buffer = vb;
                            state.vertex_buffer_cap = vb_desc.ByteWidth as usize;
                        }
                    }

                    // Create / Reallocate dynamic Index Buffer
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
                        if (unsafe { state.device.CreateBuffer(&ib_desc, None, Some(&mut ib)) }).is_ok() {
                            state.index_buffer = ib;
                            state.index_buffer_cap = ib_desc.ByteWidth as usize;
                        }
                    }

                    // Map and write vertices
                    if let Some(vb) = state.vertex_buffer.as_ref() {
                        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                        if (unsafe { state.context.Map(vb, 0, D3D11_MAP_WRITE_DISCARD, 0, Some(&mut mapped)) }).is_ok() {
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    mesh.vertices.as_ptr() as *const c_void,
                                    mapped.pData,
                                    vb_byte_size,
                                );
                                state.context.Unmap(vb, 0);
                            }
                        }
                    }

                    // Map and write indices
                    if let Some(ib) = state.index_buffer.as_ref() {
                        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                        if (unsafe { state.context.Map(ib, 0, D3D11_MAP_WRITE_DISCARD, 0, Some(&mut mapped)) }).is_ok() {
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    mesh.indices.as_ptr() as *const c_void,
                                    mapped.pData,
                                    ib_byte_size,
                                );
                                state.context.Unmap(ib, 0);
                            }
                        }
                    }

                    // Bind buffers and draw
                    if let (Some(vb), Some(ib)) = (state.vertex_buffer.as_ref(), state.index_buffer.as_ref()) {
                        let stride = [std::mem::size_of::<egui::epaint::Vertex>() as u32];
                        let offset = [0u32];
                        let vb_opt = [Some(vb.clone())];
                        unsafe {
                            state.context.IASetVertexBuffers(0, 1, Some(vb_opt.as_ptr()), Some(stride.as_ptr()), Some(offset.as_ptr()));
                            state.context.IASetIndexBuffer(ib, DXGI_FORMAT_R32_UINT, 0);
                            state.context.IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
                            state.context.DrawIndexed(mesh.indices.len() as u32, 0, 0);
                        }
                    }
                }
            }
        }
    }));
}
