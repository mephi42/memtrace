#define __NR_exit 60

	.text
	.global _start
_start:
	mov $__NR_exit, %rax
	xor %rdi, %rdi
	syscall
