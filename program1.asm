	.ORIG x3000
	AND R0,R0,#0	;Set R0 to 0 (Stores k)
	AND R1,R1,#0	;Set R1 to 0 (Iterates possible N)
	ADD R1,R1,#1	;Set R1 to 1 (First possible N is 1)
	LDB R7,R1,#-6	;Set R7 to N
	NOT R6,R7	
	ADD R6,R6,#1	;Set R6 to -N
;To check equality: ie R1 = R2, do R1 + -R2 == 0 (Does not work for all edge cases but works in this scenario)
LOOP  AND R2,R2,#0	;Set R2 to 0
	ADD R2,R6,R1
	BRz VALID	;GOTO VALID if R1 == N
	ADD R1,R1,R1	;Multiply R1 by 4
	ADD R1,R1,R1
	BRz INVALID	;GOTO INVALID if R1 overflows (we've checked all possible N in 16 bits)
	ADD R0,R0,#2
	AND R2,R2,#0	;Check if R1 > N, R1 + -N > 0
	ADD R2,R1,R6
	BRp INVALID	;GOTO INVALID if R1 > N (Doesn't work)
	BR LOOP		;GOTO LOOP
VALID STW R0,R5,#-19	;Set x2FFF to k
	BR END
INVALID	AND R2,R2,#0
	ADD R2,R2,#-1
	STB R7,R0,#-23	;Set X2FFF to -1
END	HALT
	.END
