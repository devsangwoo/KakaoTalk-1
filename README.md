 python wrapper for LOCO protocol
=====
 
kakaotalk module is a python wrapper for LOCO protocol.

You can install this module using pip:

	pip install kakao
	easy_install kakao

## Quick Start Guide ##


### Requirement ###

First of all, you need a KakaoTalk account. Then, you have to find out 'duuid', 'sKey', and 'user_id' for your KakaoTalk account. If you need some help to extract these info from your account, see [this post](http://www.bpak.org/blog/2011/06/kakaotalk-bypassing-ssl-2/). When you are prepared, you need to specify these info to kakaotalk module. For example:

	from kakao import kakao

	kakao.duuid = 'YOUR_DUUID'
	kakao.sKey = 'YOUR_SKEY'
	kakao.user_id = 'YOUR_USER_ID'

### After you prepared ###

There are various kinds of commands in LOCO protocol like 'login', 'write', 'read', 'buy', 'checkin' etc. To use these commands freely, you have to follow two steps to make proper connection with LOCO server.

1. First, send 'checkin' command to get LOCO server info (host and port) to communicate.

		document = checkin()

		host = document['host']
		port = document['port']

2. Send handshake socket with 'login' command to LOCO server with encryption info.

		h = hand()
		l = login()
		enc_l = enc_aes(l)
		command = struct.pack('I',len(enc_l)) + enc_l
	
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((str(host),port))
		s.settimeout(5)
	
		s.send(h + command)
		reply = s.recv(40960)

Instead of using those codes, you can just simply use start() function :) For example:

	s = kakao.start()
	suc = kakao.write(s, chatId, "(하트)")
	
### Commands ###

- `buy` : get LOCO server information(HOST,PORT) from KakaoTalk
- `checkin` : literaly check in to the LOCO server
- `cwrite` : create chat room and send message
- `write` : send message to specific chat room
- `hand` : handshake command which contains encryption information
- `login` : notify to LOCO server that you will use commands (not sure)
- `chaton` : notify to LOCO server that you will start to chat with specific chat room
- `nchatlist` : get chat room list from LOCO server (not sure)
- `leave` : leave the specific chat room
- `ping` : send ping to server that notify you are still alive
- `upseen` : notify that you are checked specific chat room
- `read` : get chat room list and info from server

## License Information ##

The MIT License (MIT)

Copyright (c) 2013 s31z3th3d4y
