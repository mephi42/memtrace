#define __NR_read 3
#define __NR_exit 1
#define STDIN_FILENO 0

	.text
	.global _start
_start:
	call _base
_base:
	pop %ebp
	mov $__NR_read, %eax
	mov $STDIN_FILENO, %ebx
	lea (_ch - _base)(%ebp), %ecx
	mov $1, %edx
	int $0x80

	mov $__NR_exit, %eax
	xor %ebx, %ebx
	cmpb $'*', (_ch - _base)(%ebp)
	setne %bl
	int $0x80

	.comm _ch, 1
