#!/usr/bin/env python3
"""
ITBur-CyberAudit - Инструмент автоматического аудита безопасности Linux
Поиск уязвимостей и флагов формата bit26{...}
"""

import os
import re
import subprocess
import json
import socket
from pathlib import Path
from datetime import datetime
class CyberAuditor:
    def __init__(self):
        self.results = {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'flags_found': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
    def print_banner(self):
        """Вывод красивого баннера"""
        print("""
╔══════════════════════════════════════════════╗
║     ITBur-CyberAudit - Аудитор безопасности  ║
║     Поиск уязвимостей и флагов bit26{...}    ║
╚══════════════════════════════════════════════╝
        """)
    
    def find_flags_in_file(self, filepath):
        """Поиск флагов формата bit26{...} в файле"""
        try:
            if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    flags = re.findall(r'bit26\{[^}]+\}', content)
                    for flag in flags:
                        self.results['flags_found'].append({
                            'flag': flag,
                            'location': filepath
                        })
                        print(f"[!] НАЙДЕН ФЛАГ: {flag}")
        except:
            pass
    
    def check_file_permissions(self):
        """Блок 1: Анализ прав доступа"""
        print("\n[1] Анализ прав доступа к файлам...")

        key_dirs = ['/etc', '/var', '/home', '/root', '/tmp']
        
        # Поиск файлов с опасными правами (777, 666)
        for directory in key_dirs:
            if os.path.exists(directory):
                # Поиск файлов с правами 777
                cmd_777 = f"find {directory} -type f -perm 0777 2>/dev/null | head -10"
                result = subprocess.run(cmd_777, shell=True, capture_output=True, text=True)
                
                for filepath in result.stdout.splitlines():
                    if filepath:
                        self.results['vulnerabilities'].append({
                            'type': 'dangerous_permissions',
                            'path': filepath,
                            'permissions': '777',
                            'risk': 'Файл доступен на чтение/запись/исполнение всем пользователям'
                        })
                        self.results['recommendations'].append({
                            'issue': f'Файл {filepath} имеет права 777',
                            'fix': f'sudo chmod 644 {filepath}',
                            'description': 'Исправьте права доступа на более безопасные'
                        })
                        self.find_flags_in_file(filepath)
                # Поиск конфиденциальных файлов доступных всем
                sensitive = ['passwd', 'shadow', '*.conf', '*.bak', 'secret', 'password']
                for pattern in sensitive:
                    cmd = f"find {directory} -name '{pattern}' -perm -o=r 2>/dev/null | head -5"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    for filepath in result.stdout.splitlines():
                        if filepath:
                            self.results['vulnerabilities'].append({
                                'type': 'world_readable',
                                'path': filepath,
                                'risk': 'Конфиденциальный файл доступен для чтения всем'
                            })
                            self.results['recommendations'].append({
                                'issue': f'Файл {filepath} доступен для чтения всем',
                                'fix': f'sudo chmod 640 {filepath}',
                                'description': 'Ограничьте доступ к файлу'
                            })
                            self.find_flags_in_file(filepath)
    
    def check_network(self):
        """Блок 2: Сетевой аудит"""
        print("\n[2] Сетевой аудит...")
        
        # База знаний опасных сервисов
        dangerous_services = {
            '21': {'name': 'FTP', 'risk': 'Анонимный доступ, передача данных в открытом виде'},
            '23': {'name': 'Telnet', 'risk': 'Нешифрованное соединение, пароли в открытом виде'},
            '3306': {'name': 'MySQL', 'risk': 'Возможен доступ без пароля'},
            '5432': {'name': 'PostgreSQL', 'risk': 'Проверьте конфигурацию'},
            '139': {'name': 'SMB', 'risk': 'Потенциальные уязвимости'},
            '445': {'name': 'SMB', 'risk': 'Потенциальные уязвимости'}
        }
        # Сканирование открытых портов через ss
        cmd = "ss -tulpn 2>/dev/null | grep LISTEN"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        for line in result.stdout.splitlines():
            for port, info in dangerous_services.items():
                if f':{port}' in line:
                    self.results['vulnerabilities'].append({
                        'type': 'open_port',
                        'details': line.strip(),
                        'port': port,
                        'service': info['name'],
                        'risk': info['risk']
                    })
                    self.results['recommendations'].append({
                        'issue': f'Открыт опасный порт {port} ({info["name"]})',
                        'fix': f'sudo ufw deny {port}',
                        'description': info['risk']
                    })
        
        # Проверка FTP на анонимный доступ
        try:
            ftp_check = subprocess.run("which ftp", shell=True, capture_output=True, text=True)
            if ftp_check.returncode == 0:
                for port in [21]:
                    if any(v['port'] == str(port) for v in self.results['vulnerabilities'] if 'port' in v):
                        # Пытаемся подключиться анонимно
                        test = subprocess.run(
                            "echo 'quit' | ftp localhost 2>/dev/null | grep '230'",
                            shell=True, capture_output=True, text=True
                        )
                        if '230' in test.stdout:
                            self.results['vulnerabilities'].append({
                                'type': 'anonymous_ftp',
                                'risk': 'Анонимный доступ к FTP разрешен'
                            })
                            self.results['recommendations'].append({
                                'issue': 'FTP сервер разрешает анонимный вход',
                                'fix': 'Отключите анонимный доступ в /etc/vsftpd.conf',
                                'description': 'Анонимный FTP позволяет любому скачивать/загружать файлы'
                            })
        except:
            pass
    
    def check_packages(self):
        """Блок 3: Аудит установленных пакетов"""
        print("\n[3] Аудит установленных пакетов...")
   
        # Проверка версий критических пакетов
        critical_packages = {
            'openssh-server': 'ssh -V 2>&1',
            'apache2': 'apache2 -v 2>&1',
            'nginx': 'nginx -v 2>&1',
            'mysql-server': 'mysql --version',
            'postgresql': 'psql --version'
        }
        
        for pkg, cmd in critical_packages.items():
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    version = result.stderr if result.stderr else result.stdout
                    self.results['vulnerabilities'].append({
                        'type': 'package_info',
                        'package': pkg,
                        'version': version.strip()[:50],
                        'info': 'Проверьте актуальность версии'
                    })
            except:
                pass
        
        # Проверка установки metasploit (часто на Kali)
        msf_check = subprocess.run("which msfconsole", shell=True, capture_output=True, text=True)
        if msf_check.returncode == 0:
            self.results['vulnerabilities'].append({
                'type': 'hacking_tools',
                'details': 'Установлен Metasploit Framework',
                'risk': 'Потенциально опасные инструменты установлены в системе'
            })
    
    def check_system_info(self):
        """Дополнительная проверка системы"""
        print("\n[4] Информация о системе...")
        
        # Версия ядра
        kernel = subprocess.run("uname -a", shell=True, capture_output=True, text=True)
        self.results['system_info'] = {
            'kernel': kernel.stdout.strip(),
            'hostname': socket.gethostname()
        }
        
        # Проверка sudo прав
        sudo_check = subprocess.run("sudo -n true 2>/dev/null", shell=True)
        if sudo_check.returncode == 0:
            self.results['vulnerabilities'].append({
                'type': 'sudo_without_password',
                'risk': 'Возможно выполнение sudo без пароля'
            })
    def print_report(self):
        """Вывод отчета"""
        print("\n" + "="*60)
        print("ИТОГОВЫЙ ОТЧЕТ АУДИТА БЕЗОПАСНОСТИ")
        print("="*60)
        
        # Флаги
        print(f"\n[НАЙДЕННЫЕ ФЛАГИ: {len(self.results['flags_found'])}]")
        if self.results['flags_found']:
            for i, flag in enumerate(self.results['flags_found'], 1):
                print(f"  {i}. {flag['flag']}")
                print(f"     Локация: {flag['location']}")
        else:
            print("  Флаги не найдены")
        # Уязвимости
        print(f"\n[НАЙДЕННЫЕ УЯЗВИМОСТИ: {len(self.results['vulnerabilities'])}]")
        for i, vuln in enumerate(self.results['vulnerabilities'], 1):
            print(f"\n  {i}. Тип: {vuln.get('type', 'unknown')}")
            if 'path' in vuln:
                print(f"     Путь: {vuln['path']}")
            if 'port' in vuln:
                print(f"     Порт: {vuln['port']} ({vuln.get('service', 'unknown')})")
            if 'risk' in vuln:
                print(f"     Риск: {vuln['risk']}")
        
        # Рекомендации
        print(f"\n[РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ: {len(self.results['recommendations'])}]")
        for i, rec in enumerate(self.results['recommendations'], 1):
            print(f"\n  {i}. Проблема: {rec['issue']}")
            print(f"     Исправление: {rec['fix']}")
            print(f"     Описание: {rec['description']}")
        
        print("\n" + "="*60)
        print(f"Сканирование завершено: {self.results['scan_time']}")
        print("="*60)
        
        # Сохраняем JSON отчет
        with open('audit_report.json', 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print("\n[+] Отчет сохранен в audit_report.json")
    
    def run(self):
        """Запуск всех проверок"""
        self.print_banner()
        
        if os.geteuid() != 0:
            print("[!] Внимание: Некоторые проверки требуют прав root")
            print("[!] Рекомендуется запускать с sudo\n")
        
        self.check_file_permissions()
        self.check_network()
        self.check_packages()
        self.check_system_info()
        self.print_report()

if __name__ == "__main__":
    auditor = CyberAuditor()
    auditor.run()
