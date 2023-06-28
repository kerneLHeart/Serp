from pyfiglet import Figlet
import socket
import time
import re

# банер:
custom_fig = Figlet(font='standard')
banner = custom_fig.renderText('Se r p ')
print(banner)

#валидация ввода
ip_adr_patern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_patern = re.compile("([0-9]+)-([0-9]+)")
ports =[]

class Serp():
    # проверка валидации ip
    def check_ip(self):
        while True:
            ip_addr = input("Введите ip-адрес: ")
            if ip_adr_patern.search(ip_addr):
                #print(f"{ip_addr} действительный IP ")
                return ip_addr

    #проверка валидации порта
    def check_port(self):
        while True:
            print("Введите диапазон портов, в формате: <int>-<int> (пример: 60-120)")
            port_range = input("Введите диапазон портов: ")
            port_range_valid = port_patern.search(port_range.replace(" ", ""))
            if port_range_valid:
                port_min = int(port_range_valid.group(1))
                port_max = int(port_range_valid.group(2))
                return port_min, port_max #вернется массив [*,*]

    #сканированае
    def scan_port(self, ip, port):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#создаем сооединение с параметрами для ipv4 и tcp
            client.settimeout(0.1)# Установка тайм-аута соединения, значимо ускоряет работу программы, но если переборщить будет терять порты
            if client.connect_ex((ip, port)):
                pass
            else:
                #ports.append(port) если нам понадобятся сами порты
                print("Порт {} открыт".format(port))

        except KeyboardInterrupt:
            print("Сканирование остановлено.")
            exit()

    # функция подает порты на проверку функции scan_port
    def use_scan_port(self,ip,port):
        self.port_min = port[0]
        self.port_max = port[1]
        for prt in range(self.port_min,self.port_max+1):
            self.scan_port(ip, prt)


skan = Serp()# создаем объект класса
ip = skan.check_ip()#чекаем ip
port = skan.check_port()#чекаем порты

start_time = time.time()#время начала проги

skan.use_scan_port(ip,port)

end_time = time.time()#время конца проги
execution_time = end_time - start_time
print("Время выполнения программы:", execution_time, "секунд")
# # Этот скрипт использует API-интерфейс сокета, чтобы узнать, можно ли подключиться к порту.
# # TO DO:
# # 1. для эффективности сканирования добавить SYN сканирование,используя уже сокеты не на прикладном уровне,а на уровне сетевых интерфейсов?
# # это позволит:
# # делать различия между отфильтрованными и закрытыми портами. Также проводить сканирование более быстро и скрытно
# # 2. Выводить список служб на порте
# # 3. Выводить протокол tcp/udp