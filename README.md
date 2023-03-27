* 目前服務網址與port：(https://linux9.csie.ntu.edu.tw:8787) or (http://linux9.csie.ntu.edu.tw:9487) 第一次連上網站時，由於我們用的是self-signed certificate，Chrome會基於安全性理由跳 warning 頁面，可以在網頁上輸入thisisunsafe，即可進入頁面。
(目前已關閉)
* 如何執行：python3 main.py即可將server開在localhost port 8787(https)/9487(http)
* 備註：如果更改執行的host可能需要更動html檔中的一些連結位置，如/pages/vid.html中video tag裡面的網址
* 貼心提醒：可以先調低音量

---

##### 實作項目

* 留言板功能
* 註冊登入登出功能、Cookie
* multithread
  * Persistent HTTP
  * 可以同時處理多個request
* 加https (自己簽憑證)
* Jumpscare
* 影片串流

---

##### 組員名單

* B09902043 沈竑文
* B09902041 陳盛緯
