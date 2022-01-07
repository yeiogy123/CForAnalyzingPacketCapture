若是在command option有使用-r pcap_file，即設定從pcap_file中讀取封包。

若是在command option使用-n packet_num，從可取得的device中讀取pcap_num個封包。

若是沒有多餘的command option，則是從device中不斷讀取封包直到process被終止。

利用pcap_loop開始讀取封包。

在getPacket中處理讀到的封包以產生符合題目要求的輸出並統計每對(來源IP,目的IP)的封包數。

等pcap_loop讀完pcap_file中的封包，或是pcap_num個封包後，輸出每對(來源IP,目的IP)的封包數量。
參考資料

https://www.itread01.com/content/1546926183.html

https://dotblogs.com.tw/leo_codespace/2019/03/29/203853
希望加分

多做了sudo ./getPacket_num -n packet_num可以從裝置中讀取特定數量packet的功能，希望能加一點點的分。
