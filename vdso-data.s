# Adapted from linux/arch/x86/um/vdso/vdso.S
.section ".rodata","a",%progbits
.type vdso_start STT_OBJECT
.type vdso_end STT_OBJECT
.globl vdso_start
.globl vdso_end
vdso_start:
	.incbin "vdso.so"
vdso_end:
.set .L__sym_size_vdso_start, .-vdso_start
.size vdso_start, .L__sym_size_vdso_start
