# [WEEK07-11] 정글끝까지

```
 📢 “여기까지 잘 오셨습니다. OS프로젝트를 시작합니다.”
```

OS프로젝트는 PintOS의 코드를 직접 수정해가며 진행하는 프로젝트입니다.
PintOS는 2004년 스탠포드에서 만들어진 교육용 운영체제예요. 우리 프로젝트는 이를 기반으로 KAIST 권영진 교수님 주도 하에 만들어진 KAIST PintOS로 진행됩니다.

***
- PROJECT 1 - THREADS

    ✅ Alarm Clock  
    ✅ Priority Scheduling  
    ✅ Advanced Scheduler (Extra)  
    🚀 Result : `All 27 tests passed.`


- PROJECT 2 - USER PROGRAMS

    ✅ Argument Passing  
    ✅ User Memory Access  
    ✅ System Calls  
    ✅ Process Termination Message  
    ✅ Deny Write on Executables  
    ✅ Extend File Descriptor (Extra)  
    🚀 Result : `All 97 tests passed.`


- PROJECT 3 - VIRTUAL MEMORY

    ✅ Memory Management  
    ✅ Stack Growth  
    ✅ Memory Mapped Files  
    ✅ Swap In/Out  
    ✅ Copy on Write (Extra)  
    🚀 Result : `All 141 tests passed.`


- PROJECT 4 - FILE SYSTEM (Extra)

    🔳 Persistence Check (Introduction) [^PERS]  
    ✅ Indexed and Extensible Files  
    ✅ Subdirectories and Soft Links  
    ⬜ Buffer Cache (Extra)  
    ⬜ Synchronization [^PASS]  
    🚀 Result : `11 of 193 tests failed.`

<br>

***PROJECT TEST LOG: [TESTLOG.md](./TESTLOG.md)***  
***SUMMARY: [Arklimits' Jungle Archive](https://github.com/Arklimits/swjungle-archive/tree/main/summary/pintos)***

[^PERS]: 소단원은 없지만 Test Case가 존재함. 모두 해결하지 못했다.
[^PASS]: Synchronization Test가 PASS되는 이유는 기존에 Read 및 Write에 모두 Lock을 걸어놔서 통과는 된다.

******************

Brand new pintos for Operating Systems and Lab (CS330), KAIST, by Youngjin Kwon.

The manual is available at https://casys-kaist.github.io/pintos-kaist/.
