#include "msl/ansifp_x86.h"
/*
 * MSL x86 decimal conversion: __scalenum, __dec2num and __num2dec from ansifp_x86.obj
 * (lib/msl/MSL_X86). The library ships this object without its source; this is a
 * reconstruction, byte-identical to the object apart from relocations. The library
 * was built by an older compiler than the rest of MSL: CodeWarrior Pro 4 with
 * `/O1` (optimize for size), which keeps every local an asm block names in memory.
 */

/* MSL ansi_fp.h, x86 (SIGDIGLEN 32) */

/* static data of the original object (.data/.bss), bound to their addresses */
  /* 10^0 .. 10^31 */
    /* 10^32, 10^64, ... */
       /* set: __scalenum divides by the power of ten */

/* st(0) *= 10^eax; a negative exponent flips scale_divide */
extern char small_pow_table[];
extern char big_pow_table[];
long double *small_pow = (long double *)small_pow_table;
long double *big_pow = (long double *)big_pow_table;
long scale_divide;

static __declspec(naked) void __scalenum(void)
{
    asm
    {
        cmp     eax, 0
        jge     positive
        xor     scale_divide, 1
        neg     eax
    positive:
        fld1
        mov     ecx, eax
        mov     edx, eax
        cmp     ecx, 32
        jl      small
        and     eax, 0xffffffe0
        and     ecx, 0x1f
        fstp    st(0)
        sub     edx, eax
        shr     eax, 5
        dec     eax
        imul    eax, eax, 10
        mov     edx, big_pow
        add     edx, eax
        fld     tbyte ptr [edx]
    small:
        mov     edx, small_pow
        imul    ecx, ecx, 10
        add     edx, ecx
        fld     tbyte ptr [edx]
        fmulp   st(1), st
        cmp     scale_divide, 0
        jne     divide
        fmulp   st(1), st
        jmp     done
    divide:
        fdivp   st(1), st
    done:
        ret
    }
}

double __dec2num(const decimal *d)
{
    unsigned char bcd[10];
    double x = 0.0;
    int i;
    short cw;
    unsigned char *p = bcd;
    unsigned char b;

    /* the packed BCD operand of fbld: 18 digits, least significant pair first */
    for (i = 0; i < 9; i++) {
        b = d->sig.text[2 * i] << 4;
        bcd[9 - (i + 1)] = b | (d->sig.text[2 * i + 1] & 0xf);
    }
    bcd[9] = d->sgn;
    i = d->exp - (18 - d->sig.length);
    scale_divide = 0;
    asm
    {
        fnstcw  cw
        or      cw, 0x300
        fldcw   cw
        mov     edx, p
        fbld    tbyte ptr [edx]
        mov     eax, i
        call    __scalenum
        fstp    x
    }
    return x;
}

#define __HI(x) (*(1 + (long *)&(x)))
#define __LO(x) (*(unsigned long *)&(x))
static inline int __fpclassifyd(double x)
{
 switch (__HI(x) & 0x7ff00000) {
 case 0x7ff00000:
 if ((__HI(x) & 0x000fffff) || __LO(x)) return 1;
 return 2;
 case 0:
 if ((__HI(x) & 0x000fffff) || __LO(x)) return 5;
 return 3;
 default: return 4;
 }
}
static inline int __signbitd(double x) { return __HI(x) & 0x80000000; }
void __num2dec(const decform *f, double x, decimal *d)
{
 short cw = 0x37f;
 float bias = 17.0f;
 short savecw;
 double big = 1.0e17;
 double ten = 10.0;
 unsigned char *text = d->sig.text;
 d->sgn = (char)(__signbitd(x) >> 31);
 switch (__fpclassifyd(x)) {
 case 1: d->sig.text[0] = 'N'; d->sig.length = 1; return;
 case 2: d->sig.text[0] = 'I'; d->sig.length = 1; return;
 case 3: d->sig.text[0] = '0'; d->sig.length = 1; return;
 case 4:
 case 5:
 scale_divide = 1;
 asm {
 fnstcw savecw
 fldcw cw
 fld qword ptr x
 fabs
 fld st(0)
 fxtract
 fxch st(1)
 fstp st(1)
 fldlg2
 fmulp st(1), st
 fsub bias
 mov eax, d
 fistp dword ptr [eax + 2]
 mov eax, dword ptr [eax + 2]
 call __scalenum
 fld big
 fcomp st(1)
 fnstsw ax
 sahf
 jbe skip
 fmul ten
 mov eax, d
 dec dword ptr [eax + 2]
skip:
 sub esp, 14
 mov eax, text
 fbstp tbyte ptr [esp + 4]
 mov ecx, 9
next:
 dec ecx
 mov dl, byte ptr [esp + ecx + 4]
 mov dh, dl
 shr dl, 4
 and dx, 0x0f0f
 or dx, 0x3030
 mov word ptr [eax], dx
 add eax, 2
 jecxz done
 jmp next
done:
 add esp, 14
 fldcw savecw
 }
 default: d->sig.length = 18;
 }
}
