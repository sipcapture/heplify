
//line machine.rl:1
package internal


//line machine.go:7
const decoder_start int = 1
const decoder_first_final int = 74
const decoder_error int = 0

const decoder_en_main int = 1


//line machine.rl:6


func ParseCSeq(data []byte) (c []byte) {
	cs, p, pe := 0, 0, len(data)
	mark := 0

	
//line machine.go:23
	{
	cs = decoder_start
	}

//line machine.go:28
	{
	if p == pe {
		goto _test_eof
	}
	switch cs {
	case 1:
		goto st_case_1
	case 2:
		goto st_case_2
	case 3:
		goto st_case_3
	case 4:
		goto st_case_4
	case 5:
		goto st_case_5
	case 6:
		goto st_case_6
	case 7:
		goto st_case_7
	case 8:
		goto st_case_8
	case 9:
		goto st_case_9
	case 10:
		goto st_case_10
	case 11:
		goto st_case_11
	case 12:
		goto st_case_12
	case 13:
		goto st_case_13
	case 14:
		goto st_case_14
	case 15:
		goto st_case_15
	case 16:
		goto st_case_16
	case 17:
		goto st_case_17
	case 18:
		goto st_case_18
	case 0:
		goto st_case_0
	case 74:
		goto st_case_74
	case 19:
		goto st_case_19
	case 20:
		goto st_case_20
	case 21:
		goto st_case_21
	case 22:
		goto st_case_22
	case 23:
		goto st_case_23
	case 24:
		goto st_case_24
	case 25:
		goto st_case_25
	case 26:
		goto st_case_26
	case 27:
		goto st_case_27
	case 28:
		goto st_case_28
	case 29:
		goto st_case_29
	case 30:
		goto st_case_30
	case 31:
		goto st_case_31
	case 32:
		goto st_case_32
	case 33:
		goto st_case_33
	case 34:
		goto st_case_34
	case 35:
		goto st_case_35
	case 36:
		goto st_case_36
	case 37:
		goto st_case_37
	case 38:
		goto st_case_38
	case 39:
		goto st_case_39
	case 40:
		goto st_case_40
	case 41:
		goto st_case_41
	case 42:
		goto st_case_42
	case 43:
		goto st_case_43
	case 44:
		goto st_case_44
	case 45:
		goto st_case_45
	case 46:
		goto st_case_46
	case 47:
		goto st_case_47
	case 48:
		goto st_case_48
	case 49:
		goto st_case_49
	case 50:
		goto st_case_50
	case 51:
		goto st_case_51
	case 52:
		goto st_case_52
	case 53:
		goto st_case_53
	case 54:
		goto st_case_54
	case 55:
		goto st_case_55
	case 56:
		goto st_case_56
	case 57:
		goto st_case_57
	case 58:
		goto st_case_58
	case 59:
		goto st_case_59
	case 60:
		goto st_case_60
	case 61:
		goto st_case_61
	case 62:
		goto st_case_62
	case 63:
		goto st_case_63
	case 64:
		goto st_case_64
	case 65:
		goto st_case_65
	case 66:
		goto st_case_66
	case 67:
		goto st_case_67
	case 68:
		goto st_case_68
	case 69:
		goto st_case_69
	case 70:
		goto st_case_70
	case 71:
		goto st_case_71
	case 72:
		goto st_case_72
	case 73:
		goto st_case_73
	}
	goto st_out
	st1:
		if p++; p == pe {
			goto _test_eof1
		}
	st_case_1:
		switch data[p] {
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st2:
		if p++; p == pe {
			goto _test_eof2
		}
	st_case_2:
		switch data[p] {
		case 67:
			goto st2
		case 83:
			goto st3
		case 99:
			goto st2
		case 115:
			goto st3
		}
		goto st1
	st3:
		if p++; p == pe {
			goto _test_eof3
		}
	st_case_3:
		switch data[p] {
		case 67:
			goto st2
		case 69:
			goto st4
		case 99:
			goto st2
		case 101:
			goto st4
		}
		goto st1
	st4:
		if p++; p == pe {
			goto _test_eof4
		}
	st_case_4:
		switch data[p] {
		case 67:
			goto st2
		case 81:
			goto st5
		case 99:
			goto st2
		case 113:
			goto st5
		}
		goto st1
	st5:
		if p++; p == pe {
			goto _test_eof5
		}
	st_case_5:
		switch data[p] {
		case 9:
			goto st5
		case 32:
			goto st5
		case 58:
			goto st6
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st6:
		if p++; p == pe {
			goto _test_eof6
		}
	st_case_6:
		switch data[p] {
		case 9:
			goto st6
		case 13:
			goto st7
		case 32:
			goto st6
		case 67:
			goto st2
		case 99:
			goto st2
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto st10
		}
		goto st1
	st7:
		if p++; p == pe {
			goto _test_eof7
		}
	st_case_7:
		switch data[p] {
		case 10:
			goto st8
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st8:
		if p++; p == pe {
			goto _test_eof8
		}
	st_case_8:
		switch data[p] {
		case 9:
			goto st9
		case 32:
			goto st9
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st9:
		if p++; p == pe {
			goto _test_eof9
		}
	st_case_9:
		switch data[p] {
		case 9:
			goto st9
		case 32:
			goto st9
		case 67:
			goto st2
		case 99:
			goto st2
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto st10
		}
		goto st1
	st10:
		if p++; p == pe {
			goto _test_eof10
		}
	st_case_10:
		switch data[p] {
		case 9:
			goto st11
		case 13:
			goto st12
		case 32:
			goto st11
		case 67:
			goto st2
		case 99:
			goto st2
		}
		if 48 <= data[p] && data[p] <= 57 {
			goto st10
		}
		goto st1
	st11:
		if p++; p == pe {
			goto _test_eof11
		}
	st_case_11:
		switch data[p] {
		case 9:
			goto st11
		case 13:
			goto st12
		case 32:
			goto st11
		case 65:
			goto tr12
		case 66:
			goto tr13
		case 67:
			goto tr14
		case 73:
			goto tr15
		case 75:
			goto tr16
		case 77:
			goto tr17
		case 78:
			goto tr18
		case 79:
			goto tr19
		case 80:
			goto tr20
		case 82:
			goto tr21
		case 83:
			goto tr22
		case 85:
			goto tr23
		case 99:
			goto st2
		}
		goto st1
	st12:
		if p++; p == pe {
			goto _test_eof12
		}
	st_case_12:
		switch data[p] {
		case 10:
			goto st13
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st13:
		if p++; p == pe {
			goto _test_eof13
		}
	st_case_13:
		switch data[p] {
		case 9:
			goto st14
		case 32:
			goto st14
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st14:
		if p++; p == pe {
			goto _test_eof14
		}
	st_case_14:
		switch data[p] {
		case 9:
			goto st14
		case 32:
			goto st14
		case 65:
			goto tr12
		case 66:
			goto tr13
		case 67:
			goto tr14
		case 73:
			goto tr15
		case 75:
			goto tr16
		case 77:
			goto tr17
		case 78:
			goto tr18
		case 79:
			goto tr19
		case 80:
			goto tr20
		case 82:
			goto tr21
		case 83:
			goto tr22
		case 85:
			goto tr23
		case 99:
			goto st2
		}
		goto st1
tr12:
//line machine.rl:41

			mark = p
		
	goto st15
	st15:
		if p++; p == pe {
			goto _test_eof15
		}
	st_case_15:
//line machine.go:474
		switch data[p] {
		case 67:
			goto st16
		case 99:
			goto st2
		}
		goto st1
	st16:
		if p++; p == pe {
			goto _test_eof16
		}
	st_case_16:
		switch data[p] {
		case 67:
			goto st2
		case 75:
			goto st17
		case 83:
			goto st3
		case 99:
			goto st2
		case 115:
			goto st3
		}
		goto st1
	st17:
		if p++; p == pe {
			goto _test_eof17
		}
	st_case_17:
		switch data[p] {
		case 13:
			goto tr28
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
tr28:
//line machine.rl:45

			c=data[mark:p]
		
	goto st18
	st18:
		if p++; p == pe {
			goto _test_eof18
		}
	st_case_18:
//line machine.go:525
		if data[p] == 10 {
			goto tr29
		}
		goto st0
st_case_0:
	st0:
		cs = 0
		goto _out
tr29:
//line machine.rl:50
 return c 
	goto st74
	st74:
		if p++; p == pe {
			goto _test_eof74
		}
	st_case_74:
//line machine.go:543
		goto st0
tr13:
//line machine.rl:41

			mark = p
		
	goto st19
	st19:
		if p++; p == pe {
			goto _test_eof19
		}
	st_case_19:
//line machine.go:556
		switch data[p] {
		case 67:
			goto st2
		case 89:
			goto st20
		case 99:
			goto st2
		}
		goto st1
	st20:
		if p++; p == pe {
			goto _test_eof20
		}
	st_case_20:
		switch data[p] {
		case 67:
			goto st2
		case 69:
			goto st17
		case 99:
			goto st2
		}
		goto st1
tr14:
//line machine.rl:41

			mark = p
		
	goto st21
	st21:
		if p++; p == pe {
			goto _test_eof21
		}
	st_case_21:
//line machine.go:591
		switch data[p] {
		case 65:
			goto st22
		case 67:
			goto st2
		case 83:
			goto st3
		case 99:
			goto st2
		case 115:
			goto st3
		}
		goto st1
	st22:
		if p++; p == pe {
			goto _test_eof22
		}
	st_case_22:
		switch data[p] {
		case 67:
			goto st2
		case 78:
			goto st23
		case 99:
			goto st2
		}
		goto st1
	st23:
		if p++; p == pe {
			goto _test_eof23
		}
	st_case_23:
		switch data[p] {
		case 67:
			goto st24
		case 99:
			goto st2
		}
		goto st1
	st24:
		if p++; p == pe {
			goto _test_eof24
		}
	st_case_24:
		switch data[p] {
		case 67:
			goto st2
		case 69:
			goto st25
		case 83:
			goto st3
		case 99:
			goto st2
		case 115:
			goto st3
		}
		goto st1
	st25:
		if p++; p == pe {
			goto _test_eof25
		}
	st_case_25:
		switch data[p] {
		case 67:
			goto st2
		case 76:
			goto st17
		case 99:
			goto st2
		}
		goto st1
tr15:
//line machine.rl:41

			mark = p
		
	goto st26
	st26:
		if p++; p == pe {
			goto _test_eof26
		}
	st_case_26:
//line machine.go:674
		switch data[p] {
		case 67:
			goto st2
		case 78:
			goto st27
		case 99:
			goto st2
		}
		goto st1
	st27:
		if p++; p == pe {
			goto _test_eof27
		}
	st_case_27:
		switch data[p] {
		case 67:
			goto st2
		case 70:
			goto st28
		case 86:
			goto st29
		case 99:
			goto st2
		}
		goto st1
	st28:
		if p++; p == pe {
			goto _test_eof28
		}
	st_case_28:
		switch data[p] {
		case 67:
			goto st2
		case 79:
			goto st17
		case 99:
			goto st2
		}
		goto st1
	st29:
		if p++; p == pe {
			goto _test_eof29
		}
	st_case_29:
		switch data[p] {
		case 67:
			goto st2
		case 73:
			goto st30
		case 99:
			goto st2
		}
		goto st1
	st30:
		if p++; p == pe {
			goto _test_eof30
		}
	st_case_30:
		switch data[p] {
		case 67:
			goto st2
		case 84:
			goto st20
		case 99:
			goto st2
		}
		goto st1
tr16:
//line machine.rl:41

			mark = p
		
	goto st31
	st31:
		if p++; p == pe {
			goto _test_eof31
		}
	st_case_31:
//line machine.go:753
		switch data[p] {
		case 67:
			goto st2
		case 68:
			goto st32
		case 99:
			goto st2
		}
		goto st1
	st32:
		if p++; p == pe {
			goto _test_eof32
		}
	st_case_32:
		switch data[p] {
		case 67:
			goto st2
		case 77:
			goto st33
		case 99:
			goto st2
		}
		goto st1
	st33:
		if p++; p == pe {
			goto _test_eof33
		}
	st_case_33:
		switch data[p] {
		case 67:
			goto st2
		case 81:
			goto st17
		case 99:
			goto st2
		}
		goto st1
tr17:
//line machine.rl:41

			mark = p
		
	goto st34
	st34:
		if p++; p == pe {
			goto _test_eof34
		}
	st_case_34:
//line machine.go:802
		switch data[p] {
		case 67:
			goto st2
		case 69:
			goto st35
		case 99:
			goto st2
		}
		goto st1
	st35:
		if p++; p == pe {
			goto _test_eof35
		}
	st_case_35:
		switch data[p] {
		case 67:
			goto st2
		case 83:
			goto st36
		case 99:
			goto st2
		}
		goto st1
	st36:
		if p++; p == pe {
			goto _test_eof36
		}
	st_case_36:
		switch data[p] {
		case 67:
			goto st2
		case 83:
			goto st37
		case 99:
			goto st2
		}
		goto st1
	st37:
		if p++; p == pe {
			goto _test_eof37
		}
	st_case_37:
		switch data[p] {
		case 65:
			goto st38
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st38:
		if p++; p == pe {
			goto _test_eof38
		}
	st_case_38:
		switch data[p] {
		case 67:
			goto st2
		case 71:
			goto st20
		case 99:
			goto st2
		}
		goto st1
tr18:
//line machine.rl:41

			mark = p
		
	goto st39
	st39:
		if p++; p == pe {
			goto _test_eof39
		}
	st_case_39:
//line machine.go:879
		switch data[p] {
		case 67:
			goto st2
		case 79:
			goto st40
		case 99:
			goto st2
		}
		goto st1
	st40:
		if p++; p == pe {
			goto _test_eof40
		}
	st_case_40:
		switch data[p] {
		case 67:
			goto st2
		case 84:
			goto st41
		case 99:
			goto st2
		}
		goto st1
	st41:
		if p++; p == pe {
			goto _test_eof41
		}
	st_case_41:
		switch data[p] {
		case 67:
			goto st2
		case 73:
			goto st42
		case 99:
			goto st2
		}
		goto st1
	st42:
		if p++; p == pe {
			goto _test_eof42
		}
	st_case_42:
		switch data[p] {
		case 67:
			goto st2
		case 70:
			goto st43
		case 99:
			goto st2
		}
		goto st1
	st43:
		if p++; p == pe {
			goto _test_eof43
		}
	st_case_43:
		switch data[p] {
		case 67:
			goto st2
		case 89:
			goto st17
		case 99:
			goto st2
		}
		goto st1
tr19:
//line machine.rl:41

			mark = p
		
	goto st44
	st44:
		if p++; p == pe {
			goto _test_eof44
		}
	st_case_44:
//line machine.go:956
		switch data[p] {
		case 67:
			goto st2
		case 80:
			goto st45
		case 99:
			goto st2
		}
		goto st1
	st45:
		if p++; p == pe {
			goto _test_eof45
		}
	st_case_45:
		switch data[p] {
		case 67:
			goto st2
		case 84:
			goto st46
		case 99:
			goto st2
		}
		goto st1
	st46:
		if p++; p == pe {
			goto _test_eof46
		}
	st_case_46:
		switch data[p] {
		case 67:
			goto st2
		case 73:
			goto st47
		case 99:
			goto st2
		}
		goto st1
	st47:
		if p++; p == pe {
			goto _test_eof47
		}
	st_case_47:
		switch data[p] {
		case 67:
			goto st2
		case 79:
			goto st48
		case 99:
			goto st2
		}
		goto st1
	st48:
		if p++; p == pe {
			goto _test_eof48
		}
	st_case_48:
		switch data[p] {
		case 67:
			goto st2
		case 78:
			goto st49
		case 99:
			goto st2
		}
		goto st1
	st49:
		if p++; p == pe {
			goto _test_eof49
		}
	st_case_49:
		switch data[p] {
		case 67:
			goto st2
		case 83:
			goto st17
		case 99:
			goto st2
		}
		goto st1
tr20:
//line machine.rl:41

			mark = p
		
	goto st50
	st50:
		if p++; p == pe {
			goto _test_eof50
		}
	st_case_50:
//line machine.go:1047
		switch data[p] {
		case 67:
			goto st2
		case 82:
			goto st51
		case 85:
			goto st52
		case 99:
			goto st2
		}
		goto st1
	st51:
		if p++; p == pe {
			goto _test_eof51
		}
	st_case_51:
		switch data[p] {
		case 65:
			goto st15
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st52:
		if p++; p == pe {
			goto _test_eof52
		}
	st_case_52:
		switch data[p] {
		case 66:
			goto st53
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st53:
		if p++; p == pe {
			goto _test_eof53
		}
	st_case_53:
		switch data[p] {
		case 67:
			goto st2
		case 76:
			goto st54
		case 99:
			goto st2
		}
		goto st1
	st54:
		if p++; p == pe {
			goto _test_eof54
		}
	st_case_54:
		switch data[p] {
		case 67:
			goto st2
		case 73:
			goto st55
		case 99:
			goto st2
		}
		goto st1
	st55:
		if p++; p == pe {
			goto _test_eof55
		}
	st_case_55:
		switch data[p] {
		case 67:
			goto st2
		case 83:
			goto st56
		case 99:
			goto st2
		}
		goto st1
	st56:
		if p++; p == pe {
			goto _test_eof56
		}
	st_case_56:
		switch data[p] {
		case 67:
			goto st2
		case 72:
			goto st17
		case 99:
			goto st2
		}
		goto st1
tr21:
//line machine.rl:41

			mark = p
		
	goto st57
	st57:
		if p++; p == pe {
			goto _test_eof57
		}
	st_case_57:
//line machine.go:1154
		switch data[p] {
		case 67:
			goto st2
		case 69:
			goto st58
		case 99:
			goto st2
		}
		goto st1
	st58:
		if p++; p == pe {
			goto _test_eof58
		}
	st_case_58:
		switch data[p] {
		case 67:
			goto st2
		case 70:
			goto st59
		case 71:
			goto st61
		case 99:
			goto st2
		}
		goto st1
	st59:
		if p++; p == pe {
			goto _test_eof59
		}
	st_case_59:
		switch data[p] {
		case 67:
			goto st2
		case 69:
			goto st60
		case 99:
			goto st2
		}
		goto st1
	st60:
		if p++; p == pe {
			goto _test_eof60
		}
	st_case_60:
		switch data[p] {
		case 67:
			goto st2
		case 82:
			goto st17
		case 99:
			goto st2
		}
		goto st1
	st61:
		if p++; p == pe {
			goto _test_eof61
		}
	st_case_61:
		switch data[p] {
		case 67:
			goto st2
		case 73:
			goto st62
		case 99:
			goto st2
		}
		goto st1
	st62:
		if p++; p == pe {
			goto _test_eof62
		}
	st_case_62:
		switch data[p] {
		case 67:
			goto st2
		case 83:
			goto st63
		case 99:
			goto st2
		}
		goto st1
	st63:
		if p++; p == pe {
			goto _test_eof63
		}
	st_case_63:
		switch data[p] {
		case 67:
			goto st2
		case 84:
			goto st59
		case 99:
			goto st2
		}
		goto st1
tr22:
//line machine.rl:41

			mark = p
		
	goto st64
	st64:
		if p++; p == pe {
			goto _test_eof64
		}
	st_case_64:
//line machine.go:1261
		switch data[p] {
		case 67:
			goto st2
		case 85:
			goto st65
		case 99:
			goto st2
		}
		goto st1
	st65:
		if p++; p == pe {
			goto _test_eof65
		}
	st_case_65:
		switch data[p] {
		case 66:
			goto st66
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st66:
		if p++; p == pe {
			goto _test_eof66
		}
	st_case_66:
		switch data[p] {
		case 67:
			goto st2
		case 83:
			goto st67
		case 99:
			goto st2
		}
		goto st1
	st67:
		if p++; p == pe {
			goto _test_eof67
		}
	st_case_67:
		switch data[p] {
		case 67:
			goto st68
		case 99:
			goto st2
		}
		goto st1
	st68:
		if p++; p == pe {
			goto _test_eof68
		}
	st_case_68:
		switch data[p] {
		case 67:
			goto st2
		case 82:
			goto st69
		case 83:
			goto st3
		case 99:
			goto st2
		case 115:
			goto st3
		}
		goto st1
	st69:
		if p++; p == pe {
			goto _test_eof69
		}
	st_case_69:
		switch data[p] {
		case 67:
			goto st2
		case 73:
			goto st70
		case 99:
			goto st2
		}
		goto st1
	st70:
		if p++; p == pe {
			goto _test_eof70
		}
	st_case_70:
		switch data[p] {
		case 66:
			goto st20
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
tr23:
//line machine.rl:41

			mark = p
		
	goto st71
	st71:
		if p++; p == pe {
			goto _test_eof71
		}
	st_case_71:
//line machine.go:1368
		switch data[p] {
		case 67:
			goto st2
		case 80:
			goto st72
		case 99:
			goto st2
		}
		goto st1
	st72:
		if p++; p == pe {
			goto _test_eof72
		}
	st_case_72:
		switch data[p] {
		case 67:
			goto st2
		case 68:
			goto st73
		case 99:
			goto st2
		}
		goto st1
	st73:
		if p++; p == pe {
			goto _test_eof73
		}
	st_case_73:
		switch data[p] {
		case 65:
			goto st30
		case 67:
			goto st2
		case 99:
			goto st2
		}
		goto st1
	st_out:
	_test_eof1: cs = 1; goto _test_eof
	_test_eof2: cs = 2; goto _test_eof
	_test_eof3: cs = 3; goto _test_eof
	_test_eof4: cs = 4; goto _test_eof
	_test_eof5: cs = 5; goto _test_eof
	_test_eof6: cs = 6; goto _test_eof
	_test_eof7: cs = 7; goto _test_eof
	_test_eof8: cs = 8; goto _test_eof
	_test_eof9: cs = 9; goto _test_eof
	_test_eof10: cs = 10; goto _test_eof
	_test_eof11: cs = 11; goto _test_eof
	_test_eof12: cs = 12; goto _test_eof
	_test_eof13: cs = 13; goto _test_eof
	_test_eof14: cs = 14; goto _test_eof
	_test_eof15: cs = 15; goto _test_eof
	_test_eof16: cs = 16; goto _test_eof
	_test_eof17: cs = 17; goto _test_eof
	_test_eof18: cs = 18; goto _test_eof
	_test_eof74: cs = 74; goto _test_eof
	_test_eof19: cs = 19; goto _test_eof
	_test_eof20: cs = 20; goto _test_eof
	_test_eof21: cs = 21; goto _test_eof
	_test_eof22: cs = 22; goto _test_eof
	_test_eof23: cs = 23; goto _test_eof
	_test_eof24: cs = 24; goto _test_eof
	_test_eof25: cs = 25; goto _test_eof
	_test_eof26: cs = 26; goto _test_eof
	_test_eof27: cs = 27; goto _test_eof
	_test_eof28: cs = 28; goto _test_eof
	_test_eof29: cs = 29; goto _test_eof
	_test_eof30: cs = 30; goto _test_eof
	_test_eof31: cs = 31; goto _test_eof
	_test_eof32: cs = 32; goto _test_eof
	_test_eof33: cs = 33; goto _test_eof
	_test_eof34: cs = 34; goto _test_eof
	_test_eof35: cs = 35; goto _test_eof
	_test_eof36: cs = 36; goto _test_eof
	_test_eof37: cs = 37; goto _test_eof
	_test_eof38: cs = 38; goto _test_eof
	_test_eof39: cs = 39; goto _test_eof
	_test_eof40: cs = 40; goto _test_eof
	_test_eof41: cs = 41; goto _test_eof
	_test_eof42: cs = 42; goto _test_eof
	_test_eof43: cs = 43; goto _test_eof
	_test_eof44: cs = 44; goto _test_eof
	_test_eof45: cs = 45; goto _test_eof
	_test_eof46: cs = 46; goto _test_eof
	_test_eof47: cs = 47; goto _test_eof
	_test_eof48: cs = 48; goto _test_eof
	_test_eof49: cs = 49; goto _test_eof
	_test_eof50: cs = 50; goto _test_eof
	_test_eof51: cs = 51; goto _test_eof
	_test_eof52: cs = 52; goto _test_eof
	_test_eof53: cs = 53; goto _test_eof
	_test_eof54: cs = 54; goto _test_eof
	_test_eof55: cs = 55; goto _test_eof
	_test_eof56: cs = 56; goto _test_eof
	_test_eof57: cs = 57; goto _test_eof
	_test_eof58: cs = 58; goto _test_eof
	_test_eof59: cs = 59; goto _test_eof
	_test_eof60: cs = 60; goto _test_eof
	_test_eof61: cs = 61; goto _test_eof
	_test_eof62: cs = 62; goto _test_eof
	_test_eof63: cs = 63; goto _test_eof
	_test_eof64: cs = 64; goto _test_eof
	_test_eof65: cs = 65; goto _test_eof
	_test_eof66: cs = 66; goto _test_eof
	_test_eof67: cs = 67; goto _test_eof
	_test_eof68: cs = 68; goto _test_eof
	_test_eof69: cs = 69; goto _test_eof
	_test_eof70: cs = 70; goto _test_eof
	_test_eof71: cs = 71; goto _test_eof
	_test_eof72: cs = 72; goto _test_eof
	_test_eof73: cs = 73; goto _test_eof

	_test_eof: {}
	_out: {}
	}

//line machine.rl:54

	return c
}