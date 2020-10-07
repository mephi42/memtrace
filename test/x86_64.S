#define __NR_read 0
#define __NR_exit 60
#define STDIN_FILENO 0

	.text
	.global _start
_start:
	mov $__NR_read, %rax
	mov $STDIN_FILENO, %rdi
	lea _ch(%rip), %rsi
	mov $1, %rdx
	syscall

	mov $__NR_exit, %rax
	xor %rdi, %rdi
	cmpb $'*', _ch(%rip)
	setne %dil
	syscall

	.comm _ch, 1
