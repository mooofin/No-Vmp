// Copyright (c) 2020 Can Boluk and contributors of the VTIL Project   
// All rights reserved.   
//    
// Redistribution and use in source and binary forms, with or without   
// modification, are permitted provided that the following conditions are met: 
//    
// 1. Redistributions of source code must retain the above copyright notice,   
//    this list of conditions and the following disclaimer.   
// 2. Redistributions in binary form must reproduce the above copyright   
//    notice, this list of conditions and the following disclaimer in the   
//    documentation and/or other materials provided with the distribution.   
// 3. Neither the name of VTIL Project nor the names of its contributors
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.   
//    
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE   
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR   
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF   
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS   
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN   
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)   
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  
// POSSIBILITY OF SUCH DAMAGE.        
//
#include "emulator.hpp"
#include <cstring>
#include <stdexcept>
#include <vector>
#include "rwx_allocator.hpp"

#ifndef _WIN32
#define __stdcall __attribute__ ( ( ms_abi ) )
#endif

// Helper to resolve a register to its parent 64-bit register, offset, and size
// This replaces vtil::amd64::registers.resolve_mapping()
static std::tuple<x86_reg, uint8_t, uint8_t> resolve_mapping(x86_reg reg)
{
    switch (reg)
    {
        // 64-bit registers (no offset, full size)
        case X86_REG_RAX: return { X86_REG_RAX, 0, 8 };
        case X86_REG_RBX: return { X86_REG_RBX, 0, 8 };
        case X86_REG_RCX: return { X86_REG_RCX, 0, 8 };
        case X86_REG_RDX: return { X86_REG_RDX, 0, 8 };
        case X86_REG_RSI: return { X86_REG_RSI, 0, 8 };
        case X86_REG_RDI: return { X86_REG_RDI, 0, 8 };
        case X86_REG_RBP: return { X86_REG_RBP, 0, 8 };
        case X86_REG_RSP: return { X86_REG_RSP, 0, 8 };
        case X86_REG_R8:  return { X86_REG_R8,  0, 8 };
        case X86_REG_R9:  return { X86_REG_R9,  0, 8 };
        case X86_REG_R10: return { X86_REG_R10, 0, 8 };
        case X86_REG_R11: return { X86_REG_R11, 0, 8 };
        case X86_REG_R12: return { X86_REG_R12, 0, 8 };
        case X86_REG_R13: return { X86_REG_R13, 0, 8 };
        case X86_REG_R14: return { X86_REG_R14, 0, 8 };
        case X86_REG_R15: return { X86_REG_R15, 0, 8 };
        case X86_REG_RIP: return { X86_REG_RIP, 0, 8 };
        case X86_REG_EFLAGS: return { X86_REG_EFLAGS, 0, 8 };

        // 32-bit registers (low 4 bytes)
        case X86_REG_EAX: return { X86_REG_RAX, 0, 4 };
        case X86_REG_EBX: return { X86_REG_RBX, 0, 4 };
        case X86_REG_ECX: return { X86_REG_RCX, 0, 4 };
        case X86_REG_EDX: return { X86_REG_RDX, 0, 4 };
        case X86_REG_ESI: return { X86_REG_RSI, 0, 4 };
        case X86_REG_EDI: return { X86_REG_RDI, 0, 4 };
        case X86_REG_EBP: return { X86_REG_RBP, 0, 4 };
        case X86_REG_ESP: return { X86_REG_RSP, 0, 4 };
        case X86_REG_R8D: return { X86_REG_R8,  0, 4 };
        case X86_REG_R9D: return { X86_REG_R9,  0, 4 };
        case X86_REG_R10D: return { X86_REG_R10, 0, 4 };
        case X86_REG_R11D: return { X86_REG_R11, 0, 4 };
        case X86_REG_R12D: return { X86_REG_R12, 0, 4 };
        case X86_REG_R13D: return { X86_REG_R13, 0, 4 };
        case X86_REG_R14D: return { X86_REG_R14, 0, 4 };
        case X86_REG_R15D: return { X86_REG_R15, 0, 4 };
        case X86_REG_EIP: return { X86_REG_RIP, 0, 4 };

        // 16-bit registers (low 2 bytes)
        case X86_REG_AX:  return { X86_REG_RAX, 0, 2 };
        case X86_REG_BX:  return { X86_REG_RBX, 0, 2 };
        case X86_REG_CX:  return { X86_REG_RCX, 0, 2 };
        case X86_REG_DX:  return { X86_REG_RDX, 0, 2 };
        case X86_REG_SI:  return { X86_REG_RSI, 0, 2 };
        case X86_REG_DI:  return { X86_REG_RDI, 0, 2 };
        case X86_REG_BP:  return { X86_REG_RBP, 0, 2 };
        case X86_REG_SP:  return { X86_REG_RSP, 0, 2 };
        case X86_REG_R8W: return { X86_REG_R8,  0, 2 };
        case X86_REG_R9W: return { X86_REG_R9,  0, 2 };
        case X86_REG_R10W: return { X86_REG_R10, 0, 2 };
        case X86_REG_R11W: return { X86_REG_R11, 0, 2 };
        case X86_REG_R12W: return { X86_REG_R12, 0, 2 };
        case X86_REG_R13W: return { X86_REG_R13, 0, 2 };
        case X86_REG_R14W: return { X86_REG_R14, 0, 2 };
        case X86_REG_R15W: return { X86_REG_R15, 0, 2 };
        case X86_REG_IP: return { X86_REG_RIP, 0, 2 };

        // 8-bit low registers
        case X86_REG_AL:  return { X86_REG_RAX, 0, 1 };
        case X86_REG_BL:  return { X86_REG_RBX, 0, 1 };
        case X86_REG_CL:  return { X86_REG_RCX, 0, 1 };
        case X86_REG_DL:  return { X86_REG_RDX, 0, 1 };
        case X86_REG_SIL: return { X86_REG_RSI, 0, 1 };
        case X86_REG_DIL: return { X86_REG_RDI, 0, 1 };
        case X86_REG_BPL: return { X86_REG_RBP, 0, 1 };
        case X86_REG_SPL: return { X86_REG_RSP, 0, 1 };
        case X86_REG_R8B: return { X86_REG_R8,  0, 1 };
        case X86_REG_R9B: return { X86_REG_R9,  0, 1 };
        case X86_REG_R10B: return { X86_REG_R10, 0, 1 };
        case X86_REG_R11B: return { X86_REG_R11, 0, 1 };
        case X86_REG_R12B: return { X86_REG_R12, 0, 1 };
        case X86_REG_R13B: return { X86_REG_R13, 0, 1 };
        case X86_REG_R14B: return { X86_REG_R14, 0, 1 };
        case X86_REG_R15B: return { X86_REG_R15, 0, 1 };

        // 8-bit high registers (AH, BH, CH, DH - offset 1)
        case X86_REG_AH: return { X86_REG_RAX, 1, 1 };
        case X86_REG_BH: return { X86_REG_RBX, 1, 1 };
        case X86_REG_CH: return { X86_REG_RCX, 1, 1 };
        case X86_REG_DH: return { X86_REG_RDX, 1, 1 };

        // Segment registers (not mapped to GPRs)
        // These would need special handling if used
        default:
            throw std::runtime_error("Unsupported register in resolve_mapping");
    }
}

static const std::vector<uint8_t, mem::rwx_allocator<uint8_t>> emulator_shellcode = {
	0x48, 0x89, 0xE0, 0x48, 0x89, 0xCC, 0x48, 0x83, 0xC4, 0x20, 0x48, 0x89, 0x84, 0x24,
	0x88, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x84, 0x24, 0x78, 0x01, 0x00, 0x00, 0xFF, 0x30,
	0x9C, 0x8F, 0x00, 0x9D, 0x48, 0x87, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00, 0x48, 0x87,
	0x9C, 0x24, 0x08, 0x01, 0x00, 0x00, 0x48, 0x87, 0x8C, 0x24, 0x10, 0x01, 0x00, 0x00,
	0x48, 0x87, 0x94, 0x24, 0x18, 0x01, 0x00, 0x00, 0x48, 0x87, 0xB4, 0x24, 0x20, 0x01,
	0x00, 0x00, 0x48, 0x87, 0xBC, 0x24, 0x28, 0x01, 0x00, 0x00, 0x48, 0x87, 0xAC, 0x24,
	0x30, 0x01, 0x00, 0x00, 0x4C, 0x87, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, 0x4C, 0x87,
	0x8C, 0x24, 0x40, 0x01, 0x00, 0x00, 0x4C, 0x87, 0x94, 0x24, 0x48, 0x01, 0x00, 0x00,
	0x4C, 0x87, 0x9C, 0x24, 0x50, 0x01, 0x00, 0x00, 0x4C, 0x87, 0xA4, 0x24, 0x58, 0x01,
	0x00, 0x00, 0x4C, 0x87, 0xAC, 0x24, 0x60, 0x01, 0x00, 0x00, 0x4C, 0x87, 0xB4, 0x24,
	0x68, 0x01, 0x00, 0x00, 0x4C, 0x87, 0xBC, 0x24, 0x70, 0x01, 0x00, 0x00, 0xFF, 0x94,
	0x24, 0x80, 0x01, 0x00, 0x00, 0x48, 0x87, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00, 0x48,
	0x87, 0x9C, 0x24, 0x08, 0x01, 0x00, 0x00, 0x48, 0x87, 0x8C, 0x24, 0x10, 0x01, 0x00,
	0x00, 0x48, 0x87, 0x94, 0x24, 0x18, 0x01, 0x00, 0x00, 0x48, 0x87, 0xB4, 0x24, 0x20,
	0x01, 0x00, 0x00, 0x48, 0x87, 0xBC, 0x24, 0x28, 0x01, 0x00, 0x00, 0x48, 0x87, 0xAC,
	0x24, 0x30, 0x01, 0x00, 0x00, 0x4C, 0x87, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, 0x4C,
	0x87, 0x8C, 0x24, 0x40, 0x01, 0x00, 0x00, 0x4C, 0x87, 0x94, 0x24, 0x48, 0x01, 0x00,
	0x00, 0x4C, 0x87, 0x9C, 0x24, 0x50, 0x01, 0x00, 0x00, 0x4C, 0x87, 0xA4, 0x24, 0x58,
	0x01, 0x00, 0x00, 0x4C, 0x87, 0xAC, 0x24, 0x60, 0x01, 0x00, 0x00, 0x4C, 0x87, 0xB4,
	0x24, 0x68, 0x01, 0x00, 0x00, 0x4C, 0x87, 0xBC, 0x24, 0x70, 0x01, 0x00, 0x00, 0x48,
	0x8D, 0x84, 0x24, 0x78, 0x01, 0x00, 0x00, 0xFF, 0x30, 0x9C, 0x8F, 0x00, 0x9D, 0x48,
	0x8B, 0xA4, 0x24, 0x88, 0x01, 0x00, 0x00, 0xC3
};

// Invokes routine at the pointer given with the current context and updates the context.
//
void emulator::invoke( const void* routine_pointer )
{
    // Set the runtime RIP.
    //
    __rip = routine_pointer;

	// Invoke shellcode.
	//
	( ( void( __stdcall* )( emulator* ) )emulator_shellcode.data() )( this );
}

// Resolves the offset<0> where the value is saved at for the given register
// and the number of bytes<1> it takes.
//
std::pair<int32_t, uint8_t> emulator::resolve( x86_reg reg ) const
{
    auto [base_reg, offset, size] = resolve_mapping( reg );

    const void* base;
    switch ( base_reg )
    {
        case X86_REG_RAX:	base = &v_rax;					break;
        case X86_REG_RBP:	base = &v_rbp;					break;
        case X86_REG_RBX:	base = &v_rbx;					break;
        case X86_REG_RCX:	base = &v_rcx;					break;
        case X86_REG_RDI:	base = &v_rdi;					break;
        case X86_REG_RDX:	base = &v_rdx;					break;
        case X86_REG_RSI:	base = &v_rsi;					break;
        case X86_REG_R8: 	base = &v_r8;					break;
        case X86_REG_R9: 	base = &v_r9;					break;
        case X86_REG_R10:	base = &v_r10;					break;
        case X86_REG_R11:	base = &v_r11;					break;
        case X86_REG_R12:	base = &v_r12;					break;
        case X86_REG_R13:	base = &v_r13;					break;
        case X86_REG_R14:	base = &v_r14;					break;
        case X86_REG_R15:	base = &v_r15;					break;
        default:            throw std::runtime_error("Invalid base register");
    }

    return { ( ( uint8_t* ) base - ( uint8_t* ) this ) + offset, size };
}

// Sets the value of a register.
//
emulator& emulator::set( x86_reg reg, uint64_t value )
{
    auto [off, sz] = resolve( reg );
    std::memcpy( ( uint8_t* ) this + off, &value, sz );
    return *this;
}

// Gets the value of a register.
//
uint64_t emulator::get( x86_reg reg ) const
{
    uint64_t value = 0;
    auto [off, sz] = resolve( reg );
    std::memcpy( &value, ( uint8_t* ) this + off, sz );
    return value;
}
