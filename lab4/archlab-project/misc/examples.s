	.file	"examples.c"
	.text
	.globl	sum_list
	.type	sum_list, @function
sum_list:
.LFB0:
	.cfi_startproc
	endbr64
	movq	%rdi, -24(%rsp)
	movq	$0, -8(%rsp)
	jmp	.L2
.L3:
	movq	-24(%rsp), %rax
	movq	(%rax), %rax
	addq	%rax, -8(%rsp)
	movq	-24(%rsp), %rax
	movq	8(%rax), %rax
	movq	%rax, -24(%rsp)
.L2:
	cmpq	$0, -24(%rsp)
	jne	.L3
	movq	-8(%rsp), %rax
	ret
	.cfi_endproc
.LFE0:
	.size	sum_list, .-sum_list
	.globl	rsum_list
	.type	rsum_list, @function
rsum_list:
.LFB1:
	.cfi_startproc
	endbr64
	subq	$40, %rsp
	.cfi_def_cfa_offset 48
	movq	%rdi, 8(%rsp)
	cmpq	$0, 8(%rsp)
	jne	.L6
	movl	$0, %eax
	jmp	.L7
.L6:
	movq	8(%rsp), %rax
	movq	(%rax), %rax
	movq	%rax, 16(%rsp)
	movq	8(%rsp), %rax
	movq	8(%rax), %rax
	movq	%rax, %rdi
	call	rsum_list
	movq	%rax, 24(%rsp)
	movq	16(%rsp), %rdx
	movq	24(%rsp), %rax
	addq	%rdx, %rax
.L7:
	addq	$40, %rsp
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE1:
	.size	rsum_list, .-rsum_list
	.globl	bubble_sort
	.type	bubble_sort, @function
bubble_sort:
.LFB2:
	.cfi_startproc
	endbr64
	movq	%rdi, -40(%rsp)
	movq	%rsi, -48(%rsp)
	movq	-48(%rsp), %rax
	salq	$3, %rax
	leaq	-8(%rax), %rdx
	movq	-40(%rsp), %rax
	addq	%rdx, %rax
	movq	%rax, -16(%rsp)
	jmp	.L9
.L13:
	movq	-40(%rsp), %rax
	movq	%rax, -24(%rsp)
	jmp	.L10
.L12:
	movq	-24(%rsp), %rax
	addq	$8, %rax
	movq	(%rax), %rdx
	movq	-24(%rsp), %rax
	movq	(%rax), %rax
	cmpq	%rax, %rdx
	jge	.L11
	movq	-24(%rsp), %rax
	movq	8(%rax), %rax
	movq	%rax, -8(%rsp)
	movq	-24(%rsp), %rax
	leaq	8(%rax), %rdx
	movq	-24(%rsp), %rax
	movq	(%rax), %rax
	movq	%rax, (%rdx)
	movq	-24(%rsp), %rax
	movq	-8(%rsp), %rdx
	movq	%rdx, (%rax)
.L11:
	addq	$8, -24(%rsp)
.L10:
	movq	-24(%rsp), %rax
	cmpq	-16(%rsp), %rax
	jb	.L12
	subq	$8, -16(%rsp)
.L9:
	movq	-16(%rsp), %rax
	cmpq	%rax, -40(%rsp)
	jb	.L13
	nop
	nop
	ret
	.cfi_endproc
.LFE2:
	.size	bubble_sort, .-bubble_sort
	.globl	main
	.type	main, @function
main:
.LFB3:
	.cfi_startproc
	endbr64
	movl	$0, %esi
	movl	$0, %edi
	call	bubble_sort
	movl	$0, %eax
	ret
	.cfi_endproc
.LFE3:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
