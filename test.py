# -*- coding: utf-8 -*-
from kakao import kakao

kakao.duuid = ''
kakao.sKey = ''
kakao.user_id = ''

chatId = ''

s = kakao.start()
suc = kakao.write(s, chatId, "kakao")
