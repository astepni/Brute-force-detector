#Import klas datetime i timedelta z modułu datetime. Służą one do operacji na datach i czasie.
from datetime import datetime, timedelta
#Import klasy defaultdict z modułu collections 
from collections import defaultdict

#moduł zapewniający funkcje do interakcji z systemem operacyjnym:
import os
#'os.chdir()'- zmienia bieżący katalog roboczy na podaną ścieżkę. 'os.path.dirname()': Zwraca ścieżkę do katalogu zawierającego podany plik. ;os.path.abspath() konwertuje tę ścieżkę na absolutną (pełną) ścieżkę. '__file__ to zmienna zawierająca ścieżkę do aktualnie wykonywanego skryptu.'
os.chdir(os.path.dirname(os.path.abspath(__file__)))

class BruteForceDetector:
    #Konstruktor klasy. Inicjalizuje obiekt z nazwą pliku logów i pustym słownikiem defaultdict do przechowywania prób logowania.
    def __init__(self, log_file): 
        self.log_file = log_file
        self.login_attempts = defaultdict(list)

    def parse_logs(self): # metoda zapewnia konwersję stringów dat z pliku logów na obiekty datetime.
        """Parsuje logi z pliku i zapisuje próby logowania."""
        with open(self.log_file, 'r') as file: #Otwiera plik self.log_file w trybie odczytu ('r'). "with" zapewnia prawidłowe zamknięcie pliku po zakończeniu operacji.
            for line in file: #Iteracja przez każdą linię w otwartym pliku.
                date_str, ip, status = line.strip().split(',') #przypisanie pierwszy element listy do date_str, drugi do ip, a trzeci do status.
                date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                if status == 'FAILED': #Sprawdza, czy status logowania to 'FAILED' (nieudana próba).
                    self.login_attempts[ip].append(date) #Jeśli status to 'FAILED', dodaje datę nieudanej próby do listy prób dla danego adresu IP. Jeśli pierwszy wpis dla IP - utworzenie nowej listy.

    def detect_brute_force(self, threshold=5, time_window=60):
        """
        Wykrywa próby ataku brute force.
        
        :param threshold: Liczba nieudanych prób logowania uznawana za podejrzaną
        :param time_window: Okno czasowe w sekundach do analizy prób logowania
        :return: Lista podejrzanych adresów IP
        """
        self.parse_logs() #odn. do klasy, metoda analizuje plik logów i wypełnia słownik self.login_attempts danymi o nieudanych próbach logowania.
        suspicious_ips = [] #nową, pustą listę o nazwie suspicious_ips. Do przechow. adresów IP, które zostaną uznane za podejrzane w trakcie analizy.

        for ip, attempts in self.login_attempts.items(): #Pętla for, która iteruje przez wszystkie wpisy w słowniku self.login_attempts.
            attempts.sort() #Słownik, gdzie kluczami są IP, Wartościami są listy dat nieudanych prób logowania
            for i in range(len(attempts)): #pętla iterująca przez indeksy listy attempts. range(len(attempts) - analiza każdej próby logowania, sekwencja liczb od 0 do "attempts -1"
                end_time = attempts[i] #punkt końcowy okna czasowego, który analizujemy dla prób logowania
                start_time = end_time - timedelta(seconds=time_window) #tworzy obiekt reprezentujący określony przedział czasu.
                recent_attempts = [a for a in attempts if start_time <= a <= end_time] #Wybiera wszystkie próby logowania a z listy attempts w oknie czasowym
                if len(recent_attempts) > threshold: #Sprawdza, czy liczba niedawnych prób logowania przekracza próg "threshold"
                    suspicious_ips.append(ip) #Jeśli warunek jest spełniony (liczba prób przekracza próg), adres IP jest dodawany do listy suspicious_ips. jako podejrzany
                    break #przerywa pętlę - analizę dla danego IP

        return list(set(suspicious_ips))  # Usuwamy duplikaty IP, które mogą się pojawić

    def print_summary(self, suspicious_ips): #definicja metody print summary - info o pliku logów i podejrzanych IP 
        """Wyświetla podsumowanie analizy."""
        print(f"Przeanalizowano plik logów: {self.log_file}")
        print(f"Znaleziono {len(suspicious_ips)} podejrzanych adresów IP:")
        for ip in suspicious_ips: # pętla, która iteruje przez listę suspicious_ips. ip - zmienna, która w iteracji przyj. wartość kol. elementu z listy suspicious. Lista podejrzanych IP. 
            print(f"- {ip}")
        print("Zalecane działanie: Monitoruj te adresy IP lub rozważ tymczasowe blokowanie.")

# Przykładowe wywołanie - uruchomienie skryptu progrmau głownego
if __name__ == "__main__":
    analyzer = BruteForceDetector("logs.txt")
    suspicious_ips = analyzer.detect_brute_force()
    print("Podejrzane IP:", suspicious_ips)

