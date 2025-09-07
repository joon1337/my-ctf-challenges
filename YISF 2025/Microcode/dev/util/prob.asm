_start:
    push rbp
    mov rbp, rsp

    mov rbx, 0
    mov rcx, 0
    mov rax, 0
    mov r8, 0
    call main

exit:
    mov rax, 60
    mov rdi, 0
    syscall

main:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    call print_input

    mov rdi, rbp
    sub rdi, 0x100
    mov rsi, 0x81
    call read

    mov rdi, rbp
    sub rdi, 0x80
    mov r11, [rdi]
    and r11, 0xff
    cmp r11, 0xa
    jne exit

    mov rdi, rbp
    sub rdi, 0x100
    call check
    cmp rax, 1
    je main_success
    jmp main_fail
main_success:
    call print_yisf
    mov rdi, rbp
    sub rdi, 0x100
    mov rsi, 128
    call write

    call print_brace    

    jmp exit
main_fail:
    jmp exit

check:
    push rbp
    mov rbp, rsp
    sub rsp, 0x300
    mov r11, rdi

    xor rcx, rcx
    mov rsi, rdi
    mov rdi, rsp
    call copy_flag

    mov rdi, rsp
    call sum_flag
    cmp rax, 0x21e8
    jne check_fail

    mov rdi, rsp
    call check2
    cmp rax, 1
    jne check_fail
    
    mov rdi, rsp
    call djb2
    cmp rax, 0x2ebd31af413b6c2d
    je check_success
    jne check_fail
    
check_success:
    mov rax, 1
    jmp check_done
check_fail:
    mov rax, 0
    jmp check_done

check_done:
    leave
    ret

check2:
    push rbp
    mov rbp, rsp
    sub rsp, 0x500
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    mov r11, rsp
    mov [r11], 0x312c010608070602
    add r11, 8
    mov [r11], 0x3101000002333400
    add r11, 8
    mov [r11], 0x2f282d0202010101
    add r11, 8
    mov [r11], 0x52a073532002e2f
    add r11, 8
    mov [r11], 0x2f3101003131032f
    add r11, 8
    mov [r11], 0x3202010102350501
    add r11, 8
    mov [r11], 0x320130040404332f
    add r11, 8
    mov [r11], 0x4030400002f002f
    add r11, 8
    mov [r11], 0x2c31010704020102
    add r11, 8
    mov [r11], 0x5302b0502020005
    add r11, 8
    mov [r11], 0x2322e0332302f2c
    add r11, 8
    mov [r11], 0x20104062f312e30
    add r11, 8
    mov [r11], 0x30060031042e0200
    add r11, 8
    mov [r11], 0x2012d2c05032f01
    add r11, 8
    mov [r11], 0x1342f022b31342e
    add r11, 8
    mov [r11], 0x2c023003042c30
    add r11, 8
    xor rcx, rcx
    mov r8, rdi
    mov r9, rsp
check2_loop:
    cmp rcx, 127
    je check2_success

    mov r10, [r8]
    and r10, 0xff
    add r8, 1
    
    mov r11, [r8]
    and r11, 0xff

    push rdi
    push rsi
    mov rdi, r10
    mov rsi, r11
    call greater_of
    pop rsi
    pop rdi
    cmp rax, 1
    je check2_bigger_a
    jmp check2_bigger_b

check2_bigger_a:
    mov r12, r10
    sub r12, r11
    mov r13, [r9]
    and r13, 0xff
    cmp r12, r13
    je check2_base
    jmp check2_fail

check2_bigger_b:
    mov r12, r11
    sub r12, r10
    mov r13, [r9]
    and r13, 0xff
    cmp r12, r13
    je check2_base
    jmp check2_fail

check2_base:
    add rcx, 1
    add r9, 1
    jmp check2_loop
    
check2_fail:
    mov rax, 0
    jmp check2_done
check2_success:
    mov rax, 1
    jmp check2_done
check2_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    leave
    ret

djb2:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30

    mov r8, rdi
    xor rcx, rcx
    mov rax, 5381

djb2_loop:
    cmp rcx, 128
    je djb2_done

    mov r10, rax
    mov rdi, rax
    mov rsi, 5
    call shl

    add rax, r10

    mov r10b, [r8]
    add rax, r10b

    add r8, 1
    add rcx, 1
    jmp djb2_loop

djb2_done:
    mov rsp, rbp
    pop rbp
    ret


sum_flag:
    push rcx
    push rdi
    push rdx
    xor rcx, rcx
    xor rax, rax

sum_flag_loop:
    cmp rcx, 128
    je sum_flag_loop_done
    mov rdx, [rdi]
    and rdx, 0xff
    add rax, rdx
    add rdi, 1
    add rcx, 1
    jmp sum_flag_loop

sum_flag_loop_done:
    pop rdx
    pop rdi
    pop rcx
    ret

copy_flag:
    push r12
    push r13
    xor rcx, rcx
    mov r12, rdi
    mov r13, rsi
copy_flag_loop:
    cmp rcx, 17
    je copy_flag_done
    mov rax, [r13]
    mov [r12], rax
    add r13, 8
    add r12, 8
    add rcx, 1
    jmp copy_flag_loop
copy_flag_done:
    pop r13
    pop r12
    ret

greater_of:
    push r11
    push rdi
    push rsi
    mov r11, rdi
    sub r11, rsi

    mov rdi, r11
    mov rsi, 63
    call get_bit

    cmp rax, 0
    je greater_first
    jmp greater_second

greater_first:
    mov rax, 1
    pop rsi
    pop rdi
    pop r11
    ret

greater_second:
    mov rax, 0
    pop rsi
    pop rdi
    pop r11
    ret

get_bit:
    push rbp
    mov rbp, rsp
    push rcx
    mov rcx, 1
    cmp rsi, 0
    je get_bit_skip
get_bit_loop:
    sub rsi, 1
    add rcx, rcx
    cmp rsi, 0
    jne get_bit_loop
get_bit_skip:
    mov rax, rdi
    and rax, rcx
    cmp rax, 0
    je bit_zero
    mov rax, 1
    jmp get_bit_done
bit_zero:
    xor rax, rax
get_bit_done:
    pop rcx
    mov rsp, rbp
    pop rbp
    ret

mul:
    push rbp
    mov rbp, rsp
    push rcx

    xor rax, rax
    xor rcx, rcx

mul_loop_start:
    cmp rcx, rsi
    je mul_done
    add rax, rdi
    add rcx, 1
    jmp mul_loop_start

mul_done:
    pop rcx
    mov rsp, rbp
    pop rbp
    ret

shl:
    push rbp
    mov rbp, rsp
    push rsi
    mov rax, rdi
loop_shl:
    cmp rsi, 0
    je done_shl
    add rax, rax
    sub rsi, 1
    jne loop_shl
done_shl:
    pop rsi
    mov rsp, rbp
    pop rbp
    ret

read:
    push rbp
    mov rbp, rsp
    mov rax, 0
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, 0
    syscall
    mov rsp, rbp
    pop rbp
    ret

write:
    push rbp
    mov rbp, rsp
    mov rax, 1
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, 1
    syscall
    mov rsp, rbp
    pop rbp
    ret

print_yisf:
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov r8, 0xf5fd75ff94d58a10
    mov r14, 0xf97a5f76a2a40b20
    xor r8, r14
    mov r15, 0xae81bc2b56915cdf
    mov r13, 0xbb39c6ddac6582ca
    xor r15, r13
    mov r8, 0xa9330c3c9995a801
    mov r9, 0xd6136c9e49ecaefe
    xor r8, r9
    mov r8, 0xc576e6dbeeea9499
    mov r12, 0x1b87d0c94c12356c
    xor r8, r12
    mov r9, 0xae88dcd4abfaadfe
    mov r11, 0x13f4de162a1ad0a8
    xor r9, r11
    mov r10, 0xb38af40c9daa994f
    mov r13, 0x49d66a159357f912
    xor r10, r13
    mov r11, 0x8f762e9285a1f985
    mov r12, 0x306b3b8a06c121fc
    xor r11, r12
    mov r12, 0x4f117ae42fbba961
    mov r10, 0x3608a4bfb666c4c0
    xor r12, r10
    mov r12, 0xc8f2eb0697305625
    mov r10, 0xad8f15a82cd77411
    xor r12, r10
    mov r9, 0xc00e27314b3cc4b
    mov r12, 0x7087cddae40eed28
    xor r9, r12
    mov r11, 0x5445718e61d14db5
    mov r8, 0x4b48770b5c0dd591
    xor r11, r8
    mov r12, 0xaa3c323730e33f21
    mov r8, 0x9adee881faee0264
    xor r12, r8
    mov r11, 0x843bb758a1be5dd8
    mov r14, 0x2c2b06df0c3f8436
    xor r11, r14
    mov r10, 0xea76d49cf90fee75
    mov r12, 0xd9e0f070051733a5
    xor r10, r12
    mov r14, 0xd9d58a93960d2b3d
    mov r8, 0xe788fa749601af30
    xor r14, r8
    mov r9, 0xaebc656ccfba0239
    mov r10, 0xbc54ecabc07c3860
    xor r9, r10
    mov r9, 0xde795ce97021e4b5
    mov r12, 0x8d38f8b3ca8536c2
    xor r9, r12
    mov r9, 0xf140c4b35499e5ee
    mov r13, 0xc9a7b53f1c22071e
    xor r9, r13
    mov r13, 0x422ea10e03173892
    mov r10, 0xd08f2b40df438c6
    xor r13, r10
    mov r11, 0xda58b7b512be2af3
    mov r8, 0x42d6333785fe11bb
    xor r11, r8
    mov r15, 0xc73a64617583f822
    mov r9, 0x81c3f1940eb8292a
    xor r15, r9
    mov r15, 0x186a45e9cc1af6c
    mov r10, 0x5bdc18ed4585e81d
    xor r15, r10
    mov r13, 0x3354ae8d2f7e589b
    mov r10, 0xd1e58295cac35266
    xor r13, r10
    mov r13, 0x418771960af37c2d
    mov r12, 0xb4111719e248f245
    xor r13, r12
    mov r13, 0x377087218b8508c2
    mov r11, 0x5f643592b9221425
    xor r13, r11
    mov r10, 0x1aa6d08a41c75d3d
    mov r13, 0x498cfa599b700d56
    xor r10, r13
    mov r12, 0x51a1205260e6fc6e
    mov r8, 0xbd689bd6b082b897
    xor r12, r8
    mov r11, 0x44c825f28d9e1875
    mov r8, 0x4a7dfc12b22798c3
    xor r11, r8
    mov r8, 0x2c9941fd7f9aa5f1
    mov r14, 0x980e23c89b079f96
    xor r8, r14
    mov r9, 0x25196a01655f6031
    mov r11, 0x73baa24912acd6a1
    xor r9, r11
    xor r9, r13
    xor r9, 0x1f2f326aaad0f29f
    mov rax, r9
    push rax
    mov rsi, rsp
    mov rax, 1
    mov rdi, 1
    mov rdx, 5
    syscall
    pop rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    ret

print_input:
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov r11, 0x15380d32562171c1
    mov r10, 0x555adcb98f207ed6
    xor r11, r10
    mov r15, 0x29f05d976735b50e
    mov r12, 0x28357a7adedeabb9
    xor r15, r12
    mov r12, 0xe67656b71c899abc
    mov r11, 0xc1fa0a0270f4459a
    xor r12, r11
    mov r15, 0x36e568a1a8cadc60
    mov r10, 0xd65ab97597f68e09
    xor r15, r10
    mov r14, 0x4a99de43bbec17d5
    mov r12, 0xe4bb9b55df69041d
    xor r14, r12
    mov r9, 0xca4236d3d4ed0ad9
    mov r10, 0x268e0dcdcd55318b
    xor r9, r10
    mov r11, 0x3dae8886b3bddf71
    mov r8, 0x7f4d35fa630e0ea4
    xor r11, r8
    mov r13, 0x5e077197888c69c9
    mov r10, 0x973d139cf097af23
    xor r13, r10
    mov r8, 0x74597d758a222363
    mov r15, 0x5f74147806a0e257
    xor r8, r15
    mov r10, 0xd8c16eab21788237
    mov r8, 0xc384d16800a1ded5
    xor r10, r8
    mov r13, 0x481d7b379dc2f700
    mov r9, 0x2e663de5239ac437
    xor r13, r9
    mov r13, 0x2a33d1ad4ca02d9d
    mov r14, 0xb52382c8e571a142
    xor r13, r14
    mov r12, 0xc09072093c263333
    mov r11, 0xb952169d2f6619c1
    xor r12, r11
    mov r14, 0x49d4e31ccb8653f5
    mov r8, 0x2f85cc1af4ea61dc
    xor r14, r8
    mov r14, 0x48141b403fd8addf
    mov r15, 0x4a37f166ac8ee122
    xor r14, r15
    mov r9, 0x863b14718dd2ecf
    mov r14, 0x89d42540c460470a
    xor r9, r14
    mov r13, 0x8fcd7929b0017358
    mov r12, 0xc834a51ed6435e2e
    xor r13, r12
    mov r14, 0xbb8386c3c8788c4d
    mov r13, 0x2bdcdbeb842a34eb
    xor r14, r13
    mov r11, 0xaa80c8d3a096deb7
    mov r13, 0x53abd859dbc20788
    xor r11, r13
    mov r15, 0x379e5eb4b3367f5a
    mov r11, 0x178dec648419b8c1
    xor r15, r11
    mov r15, 0xdab801416c844044
    mov r14, 0xfb2d615ce3646786
    xor r15, r14
    mov r9, 0x5c8934cbe948f5f8
    mov r12, 0xdc54e3ad9d91a263
    xor r9, r12
    mov r15, 0x6b0391c831cf706d
    mov r12, 0xb53d862b5760ee65
    xor r15, r12
    mov r11, 0xbce76ed20bf642cb
    mov r14, 0xc67a547fa59f0e94
    xor r11, r14
    mov r13, 0xf8f00924440f7cc3
    mov r14, 0x44e366069e7fb118
    xor r13, r14
    mov r8, 0xe192491ee35b8f23
    mov r10, 0x6cf64cf2ab5ac92b
    xor r8, r10
    mov r15, 0xd7f64dcc1068f517
    mov r13, 0x74d547804ccfe810
    xor r15, r13
    mov r13, 0x9aa9fc54f14c9a70
    mov r10, 0xc10df261372b3552
    xor r13, r10
    mov r14, 0xb82e7bf903b7c421
    mov r10, 0x9f6a79c076a356dd
    xor r14, r10
    mov r12, 0x9a815d8bda77b9bd
    mov r9, 0x6e7c9a57d65571c9
    xor r12, r9
    xor r12, r14
    xor r12, 0xf383e5910c4634e1
    mov rax, r12
    push rax
    mov rsi, rsp
    mov rax, 1
    mov rdi, 1
    mov rdx, 8
    syscall
    pop rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    ret

print_brace:
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r12, 0xa18876a28edd8413
    mov r13, 0x1831c393994b0bc3
    xor r12, r13
    mov r11, 0x849535b3cde41239
    mov r8, 0x86ce082f523edc14
    xor r11, r8
    mov r13, 0x25668f93703e1b27
    mov r10, 0xadb3769bf61a76a3
    xor r13, r10
    mov r14, 0x253c8499654e9d24
    mov r8, 0xa08b154c056a295e
    xor r14, r8
    mov r10, 0x3053d2ddfdcfdbbe
    mov r9, 0xa03053592f6cbdd6
    xor r10, r9
    mov r14, 0x5152fcabe4c3024
    mov r10, 0x6a439485faff8dc2
    xor r14, r10
    mov r8, 0x536cf27181dcf778
    mov r13, 0x3b4aad3a53b43ab4
    xor r8, r13
    mov r15, 0xd32a45147b0fe8ea
    mov r11, 0xeecb85dae28d15d1
    xor r15, r11
    mov r8, 0x326a7b72aa1cc6f7
    mov r11, 0x6bb10b7b796bf957
    xor r8, r11
    mov r8, 0x400052de7b36008c
    mov r12, 0x58128bb3566eb84
    xor r8, r12
    mov r8, 0xd8cdc4a38537a798
    mov r15, 0xcc2388e18e8b5efb
    xor r8, r15
    mov r9, 0xea1b7c7c1fa5e798
    mov r12, 0xcf4a16cb457f4771
    xor r9, r12
    mov r10, 0xa0ec0b336bb0afec
    mov r9, 0x80994070f477073c
    xor r10, r9
    mov r11, 0x93eec26160b04c43
    mov r14, 0xcc2683e24d157fa8
    xor r11, r14
    mov r8, 0x45cfbfb55daa58a0
    mov r11, 0x48f0ea72d1c3fbeb
    xor r8, r11
    mov r11, 0x59b24c9c6b6304af
    mov r8, 0x24b89820b1e339bf
    xor r11, r8
    mov r8, 0x53e893f5d9303473
    mov r11, 0x6ca2a8aaafbd10af
    xor r8, r11
    mov r15, 0x5f7db76c5f018af8
    mov r14, 0xc045bf83dd0d5944
    xor r15, r14
    mov r11, 0x6d037e5101062971
    mov r12, 0x3b69c35b4979f7cd
    xor r11, r12
    mov r10, 0xd7f9d78fd4d07e4c
    mov r11, 0xa9f58588f91fa230
    xor r10, r11
    mov r15, 0x8d4f5e912cfa4e0
    mov r12, 0x9f3eace19e41b3da
    xor r15, r12
    mov r15, 0x5e8339cde41151f6
    mov r10, 0x3ca3678d37d37eaa
    xor r15, r10
    mov r14, 0x6f0b1b867c2290eb
    mov r11, 0x30f074c7fe822589
    xor r14, r11
    mov r9, 0x3070abe38496a584
    mov r14, 0x58c86db0bb7c966c
    xor r9, r14
    mov r13, 0xa3e1449b4c4800b0
    mov r11, 0x1978729d30b0e53d
    xor r13, r11
    mov r13, 0x7542027f03769cd6
    mov r11, 0x356a6c641af5ff65
    xor r13, r11
    mov r15, 0x55ddce138719a6bc
    mov r14, 0x6cfc19390cbb367
    xor r15, r14
    mov r11, 0xa8e1cbc586473875
    mov r8, 0x114c1aae886ed2ef
    xor r11, r8
    mov r12, 0xeea21024b4d72f60
    mov r13, 0xcbb50aa2988b1da8
    xor r12, r13
    mov r14, 0x658cb33febe20a84
    mov r8, 0xf30054c0e70f7e70
    xor r14, r8
    xor r8, r11
    xor r8, 0x4aad85abe9269497

    mov rax, r8
    push rax
    mov rsi, rsp
    mov rax, 1
    mov rdi, 1
    mov rdx, 1
    syscall
    pop rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    ret