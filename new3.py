from typing import Protocol, List
import re
import sys
import socket
from datetime import datetime


class LogFilterProtocol(Protocol):
    def match(self, text: str) -> bool:
        pass


class SimpleLogFilter(LogFilterProtocol):
    def __init__(self, pattern: str):
        self.pattern = pattern

    def match(self, text: str) -> bool:
        try:
            return self.pattern in text
        except Exception as e:
            sys.stderr.write(f"SimpleLogFilter error: {e}\n")
            return False


class ReLogFilter(LogFilterProtocol):
    def __init__(self, pattern: str):
        try:
            self.regex = re.compile(pattern)
        except re.error as e:
            sys.stderr.write(f"Invalid regex pattern: {e}\n")
            self.regex = re.compile(r".^")  # Never matching pattern

    def match(self, text: str) -> bool:
        try:
            return bool(self.regex.search(text))
        except Exception as e:
            sys.stderr.write(f"ReLogFilter error: {e}\n")
            return False


class LevelFilter(LogFilterProtocol):
    def __init__(self, level: str):
        try:
            self.level = level.upper()
        except AttributeError as e:
            sys.stderr.write(f"Invalid level type: {e}\n")
            self.level = ""

    def match(self, text: str) -> bool:
        try:
            return text.startswith(self.level)
        except Exception as e:
            sys.stderr.write(f"LevelFilter error: {e}\n")
            return False


class LogHandlerProtocol(Protocol):
    def handle(self, text: str):
        pass


class FileHandler(LogHandlerProtocol):
    def __init__(self, filename: str):
        self.filename = filename
        self._validate_filename()

    def _validate_filename(self):
        if not isinstance(self.filename, str):
            raise ValueError("Filename must be a string")
        if not self.filename.strip():
            raise ValueError("Filename cannot be empty")
        if len(self.filename) > 255:
            raise ValueError("Filename too long")

    def _handle(self, text: str):
        try:
            with open(self.filename, "a", encoding='utf-8') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] {text}\n")
        except UnicodeEncodeError:
            with open(self.filename, "a", encoding='utf-8', errors='replace') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] [ENCODING ERROR] {text.encode('ascii', errors='replace').decode()}\n")

    def handle(self, text: str):
        try:
            self._handle(text)
        except (IOError, PermissionError) as e:
            sys.stderr.write(f"FileHandler error ({self.filename}): {e}\n")
        except Exception as e:
            sys.stderr.write(f"Unexpected FileHandler error: {e}\n")


class SocketHandler(LogHandlerProtocol):
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._validate_connection_params()

    def _validate_connection_params(self):
        if not isinstance(self.host, str):
            raise ValueError("Host must be a string")
        if not isinstance(self.port, int):
            raise ValueError("Port must be an integer")
        if not (0 <= self.port <= 65535):
            raise ValueError("Port must be between 0 and 65535")

    def handle(self, text: str):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((self.host, self.port))
                s.sendall(f"{text}\n".encode('utf-8'))
        except (socket.error, ConnectionRefusedError, TimeoutError) as e:
            sys.stderr.write(f"SocketHandler connection error ({self.host}:{self.port}): {e}\n")
        except UnicodeEncodeError:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((self.host, self.port))
                    s.sendall(f"[ENCODING ERROR] {text.encode('ascii', errors='replace').decode()}\n".encode('utf-8'))
            except Exception as e:
                sys.stderr.write(f"SocketHandler encoding error: {e}\n")
        except Exception as e:
            sys.stderr.write(f"Unexpected SocketHandler error: {e}\n")


class ConsoleHandler(LogHandlerProtocol):
    def __init__(self, use_stderr: bool = False):
        self.use_stderr = use_stderr

    def handle(self, text: str):
        try:
            if self.use_stderr:
                sys.stderr.write(f"{text}\n")
            else:
                print(text)
        except UnicodeEncodeError:
            safe_text = text.encode('ascii', errors='replace').decode()
            if self.use_stderr:
                sys.stderr.write(f"[ENCODING ERROR] {safe_text}\n")
            else:
                print(f"[ENCODING ERROR] {safe_text}")
        except Exception as e:
            sys.stderr.write(f"ConsoleHandler error: {e}\n")


class SyslogHandler(LogHandlerProtocol):
    def handle(self, text: str):
        try:
            sys.stderr.write(f"SYSLOG: {text}\n")
        except UnicodeEncodeError:
            sys.stderr.write(f"SYSLOG: [ENCODING ERROR] {text.encode('ascii', errors='replace').decode()}\n")
        except Exception as e:
            sys.stderr.write(f"SyslogHandler error: {e}\n")


class Logger:
    def __init__(self, _filters: List[LogFilterProtocol], _handlers: List[LogHandlerProtocol]):
        self.__filters = _filters or []
        self.__handlers = _handlers or []

    def log(self, text: str):
        if not isinstance(text, str):
            sys.stderr.write("Logger error: log message must be a string\n")
            return

        try:
            if all(f.match(text) for f in self.__filters):
                for handler in self.__handlers:
                    try:
                        handler.handle(text)
                    except Exception as e:
                        sys.stderr.write(f"Handler error: {e}\n")
        except Exception as e:
            sys.stderr.write(f"Logger processing error: {e}\n")


if __name__ == "__main__":
    print("Демонстрация работы системы логирования")
    
    try:
        # Создаем различные фильтры
        error_filter = SimpleLogFilter("ERROR")
        warning_filter = SimpleLogFilter("WARNING")
        digit_filter = ReLogFilter(r"\d+")
        level_filter = LevelFilter("INFO")
        
        # Создаем обработчики
        console_handler = ConsoleHandler()
        error_file_handler = FileHandler("error_logs.txt")
        all_file_handler = FileHandler("all_logs.txt")
        syslog_handler = SyslogHandler()
        
        # Пример 1: Логировать только ERROR сообщения с цифрами в консоль и файл
        print("\nПример 1: ERROR логи с цифрами")
        logger1 = Logger(
            [error_filter, digit_filter],
            [console_handler, error_file_handler]
        )
        
        logger1.log("ERROR: Ошибка 404")
        logger1.log("WARNING: Произошло что-то необычное")
        logger1.log("ERROR: Ещё ошибка")
        logger1.log(None)  # Тест обработки неверного типа
        
        # Пример 2: Логировать все INFO сообщения в файл и syslog
        print("\nПример 2: INFO логи")
        logger2 = Logger(
            [level_filter],
            [all_file_handler, syslog_handler]
        )
        
        logger2.log("INFO: Система запущена")
        logger2.log("INFO: Пользователь вошел в систему")
        logger2.log("WARNING: Мало места на диске")
        
        # Пример 3: Логировать все сообщения в консоль
        print("\nПример 3: Все логи")
        logger3 = Logger(
            [],  
            [console_handler]
        )
        
        logger3.log("DEBUG: Подробная информация")
        logger3.log("INFO: Просто для вашей информации")
        logger3.log("ERROR: Ошибка!")
        logger3.log("Специальный тест: \u2603 Unicode символ")  # Тест Unicode
        
        # Тест неверных параметров
        invalid_socket = SocketHandler("invalid_host", 99999)
        invalid_socket.handle("Test message")
        
    except Exception as e:
        sys.stderr.write(f"Fatal error in demo: {e}\n")
        sys.exit(1)