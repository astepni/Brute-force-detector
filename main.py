from datetime import datetime, timedelta
from collections import defaultdict

#moduł zapewniający funkcje do interakcji z systemem operacyjnym:
import os
#'os.chdir()'- zmienia bieżący katalog roboczy na podaną ścieżkę. 'os.path.dirname()': Zwraca ścieżkę do katalogu zawierającego podany plik. ;os.path.abspath() konwertuje tę ścieżkę na absolutną (pełną) ścieżkę. '__file__ to zmienna zawierająca ścieżkę do aktualnie wykonywanego skryptu.'
os.chdir(os.path.dirname(os.path.abspath(__file__)))

class BruteForceDetector:
    def __init__(self, log_file):
        self.log_file = log_file
        self.login_attempts = defaultdict(list)

    def parse_logs(self):
        """Parsuje logi z pliku i zapisuje próby logowania."""
        with open(self.log_file, 'r') as file:
            for line in file:
                date_str, ip, status = line.strip().split(',')
                date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                if status == 'FAILED':
                    self.login_attempts[ip].append(date)

    def detect_brute_force(self, threshold=5, time_window=60):
        """
        Wykrywa próby ataku brute force.
        
        :param threshold: Liczba nieudanych prób logowania uznawana za podejrzaną
        :param time_window: Okno czasowe w sekundach do analizy prób logowania
        :return: Lista podejrzanych adresów IP
        """
        self.parse_logs()
        suspicious_ips = []

        for ip, attempts in self.login_attempts.items():
            attempts.sort()
            for i in range(len(attempts)):
                end_time = attempts[i]
                start_time = end_time - timedelta(seconds=time_window)
                recent_attempts = [a for a in attempts if start_time <= a <= end_time]
                if len(recent_attempts) > threshold:
                    suspicious_ips.append(ip)
                    break

        return list(set(suspicious_ips))  # Usuwamy duplikaty

    def print_summary(self, suspicious_ips):
        """Wyświetla podsumowanie analizy."""
        print(f"Przeanalizowano plik logów: {self.log_file}")
        print(f"Znaleziono {len(suspicious_ips)} podejrzanych adresów IP:")
        for ip in suspicious_ips:
            print(f"- {ip}")
        print("Zalecane działanie: Monitoruj te adresy IP lub rozważ tymczasowe blokowanie.")

# Przykładowe wywołanie
if __name__ == "__main__":
    analyzer = BruteForceDetector("logs.txt")
    suspicious_ips = analyzer.detect_brute_force()
    print("Podejrzane IP:", suspicious_ips)

