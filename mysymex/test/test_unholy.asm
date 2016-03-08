 b61:	41 54                	push   %r12
 b63:	55                   	push   %rbp
 b64:	48 89 f5             	mov    %rsi,%rbp
 b67:	53                   	push   %rbx
 b68:	48 81 ec d0 13 00 00 	sub    $0x13d0,%rsp
# b6f:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
# b76:	00 00 
 b78:	48 89 84 24 c8 13 00 	mov    %rax,0x13c8(%rsp)
 b7f:	00 
 b80:	31 c0                	xor    %eax,%eax
 b82:	48 8b 06             	mov    (%rsi),%rax
# b85:	f6 c4 20             	test   $0x20,%ah
# b88:	74 09                	je     b93 <method_check_key+0x32>
# b8a:	48 c1 e8 0f          	shr    $0xf,%rax
# b8e:	83 e0 03             	and    $0x3,%eax
# b91:	eb 03                	jmp    b96 <method_check_key+0x35>
# b93:	8b 46 10             	mov    0x10(%rsi),%eax
# b96:	83 f8 09             	cmp    $0x9,%eax
# b99:	c7 44 24 08 77 68 61 	movl   %key0,0x8(%rsp)
# ba0:	74 
# ba1:	c7 44 24 0c 73 67 6f 	movl   %key1,0xc(%rsp)
# ba8:	69 
# ba9:	c7 44 24 10 6e 67 6f 	movl   %key2,0x10(%rsp)
# bb0:	6e 
# bb1:	c7 44 24 14 68 65 72 	movl   %key3,0x14(%rsp)
#===
 b99:	c7 44 24 08 77 68 61 	movl   $0x74616877,0x8(%rsp)
 ba0:	74 
 ba1:	c7 44 24 0c 73 67 6f 	movl   $0x696f6773,0xc(%rsp)
 ba8:	69 
 ba9:	c7 44 24 10 6e 67 6f 	movl   $0x6e6f676e,0x10(%rsp)
 bb0:	6e 
 bb1:	c7 44 24 14 68 65 72 	movl   $0x65726568,0x14(%rsp)
#<<<
# bb8:	65 
# bb9:	0f 85 26 01 00 00    	jne    ce5 <method_check_key+0x184>
 bbf:	48 8d 5c 24 18       	lea    0x18(%rsp),%rbx
 bc4:	45 31 e4             	xor    %r12,%r12
 bc7:	48 89 ef             	mov    %rbp,%rdi
 bca:	4c 89 e6             	mov    %r12,%rsi
## bcd:	e8 ae fd ff ff       	callq  980 <rb_ary_entry@plt>
# bd2:	a8 01                	test   $0x1,%al
# bd4:	48 89 c7             	mov    %rax,%rdi
# bd7:	74 07                	je     be0 <method_check_key+0x7f>
## bd9:	e8 32 fe ff ff       	callq  a10 <rb_fix2int@plt>
# bde:	eb 05                	jmp    be5 <method_check_key+0x84>
# be0:	e8 ab fd ff ff       	callq  990 <rb_num2int@plt>
#>>>
 be50:	42 89 04 a3          	mov    %magic0,0x0(%rbx,%r12,4)
 be51:	42 89 04 a3          	mov    %magic1,0x4(%rbx,%r12,4)
 be52:	42 89 04 a3          	mov    %magic2,0x8(%rbx,%r12,4)
 be53:	42 89 04 a3          	mov    %magic3,0xc(%rbx,%r12,4)
 be54:	42 89 04 a3          	mov    %magic4,0x10(%rbx,%r12,4)
 be55:	42 89 04 a3          	mov    %magic5,0x14(%rbx,%r12,4)
 be56:	42 89 04 a3          	mov    %magic6,0x18(%rbx,%r12,4)
 be57:	42 89 04 a3          	mov    %magic7,0x1c(%rbx,%r12,4)
 be58:	42 89 04 a3          	mov    %magic8,0x20(%rbx,%r12,4)
#===
# be5:	42 89 04 a3          	mov    %eax,(%rbx,%r12,4)
#<<<
# be9:	49 ff c4             	inc    %r12
# bec:	49 83 fc 09          	cmp    $0x9,%r12
# bf0:	75 d5                	jne    bc7 <method_check_key+0x66>
# --------
bf2:	c7 44 24 3c 20 53 73 	movl   $0x61735320,0x3c(%rsp)
bf9:	61 
bfa:	31 ff                	xor    %edi,%edi
bfc:	48 8b 04 3b          	mov    (%rbx,%rdi,1),%rax
c00:	45 31 c0             	xor    %r8d,%r8d
c03:	89 c2                	mov    %eax,%edx
c05:	48 c1 e8 20          	shr    $0x20,%rax
c09:	44 89 c1             	mov    %r8d,%ecx
c0c:	89 c6                	mov    %eax,%esi
c0e:	83 e1 03             	and    $0x3,%ecx
c11:	c1 ee 05             	shr    $0x5,%esi
c14:	44 8b 4c 8c 08       	mov    0x8(%rsp,%rcx,4),%r9d
c19:	89 c1                	mov    %eax,%ecx
c1b:	c1 e1 04             	shl    $0x4,%ecx
c1e:	31 ce                	xor    %ecx,%esi
c20:	8d 0c 06             	lea    (%rsi,%rax,1),%ecx
c23:	45 01 c1             	add    %r8d,%r9d
c26:	41 81 e8 47 86 c8 61 	sub    $0x61c88647,%r8d
c2d:	44 31 c9             	xor    %r9d,%ecx
c30:	01 ca                	add    %ecx,%edx
c32:	44 89 c1             	mov    %r8d,%ecx
c35:	c1 e9 0b             	shr    $0xb,%ecx
c38:	89 d6                	mov    %edx,%esi
c3a:	83 e1 03             	and    $0x3,%ecx
c3d:	c1 ee 05             	shr    $0x5,%esi
c40:	44 8b 4c 8c 08       	mov    0x8(%rsp,%rcx,4),%r9d
c45:	89 d1                	mov    %edx,%ecx
c47:	c1 e1 04             	shl    $0x4,%ecx
c4a:	31 ce                	xor    %ecx,%esi
c4c:	8d 0c 16             	lea    (%rsi,%rdx,1),%ecx
c4f:	45 01 c1             	add    %r8d,%r9d
c52:	44 31 c9             	xor    %r9d,%ecx
c55:	01 c8                	add    %ecx,%eax
c57:	41 81 f8 20 37 ef c6 	cmp    $0xc6ef3720,%r8d
c5e:	75 a9                	jne    c09 <method_check_key+0xa8>
c60:	48 c1 e0 20          	shl    $0x20,%rax
c64:	48 09 d0             	or     %rdx,%rax
c67:	48 89 04 3b          	mov    %rax,(%rbx,%rdi,1)
c6b:	48 83 c7 08          	add    $0x8,%rdi
c6f:	48 83 ff 28          	cmp    $0x28,%rdi
c73:	75 87                	jne    bfc <method_check_key+0x9b>
c75:	81 7c 24 3c fd f9 e3 	cmpl   $0x4de3f9fd,0x3c(%rsp)
c7c:	4d 
# c7d:	75 66                	jne    ce5 <method_check_key+0x184>
# c7f:	48 8d 5c 24 40       	lea    0x40(%rsp),%rbx
# c84:	50                   	push   %rax
# c85:	8b 44 24 40          	mov    0x40(%rsp),%eax
