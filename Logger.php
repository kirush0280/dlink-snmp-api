<?php

class Logger {
    private $logFile;
    private static $instance = null;

    private function __construct($logFile) {
        $this->logFile = $logFile;
        
        // Создаем директорию для логов, если она не существует
        $logDir = dirname($logFile);
        if (!file_exists($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }

    public static function getInstance($logFile = null) {
        if (self::$instance === null) {
            if ($logFile === null) {
                $logFile = dirname(__FILE__) . '/logs/snmp_api.log';
            }
            self::$instance = new self($logFile);
        }
        return self::$instance;
    }

    public function log($message, $level = 'INFO') {
        $timestamp = date('Y-m-d H:i:s');
        $formattedMessage = sprintf("[%s] [%s] %s\n", $timestamp, $level, $message);
        
        file_put_contents($this->logFile, $formattedMessage, FILE_APPEND);
    }

    public function info($message) {
        $this->log($message, 'INFO');
    }

    public function error($message) {
        $this->log($message, 'ERROR');
    }

    public function debug($message) {
        $this->log($message, 'DEBUG');
    }

    public function warning($message) {
        $this->log($message, 'WARNING');
    }

    public function getLogPath() {
        return $this->logFile;
    }

    // Метод для очистки старых логов (оставляет только логи за последние N дней)
    public function cleanOldLogs($daysToKeep = 30) {
        $logDir = dirname($this->logFile);
        $currentLog = basename($this->logFile);
        
        if (file_exists($logDir)) {
            foreach (scandir($logDir) as $file) {
                $filePath = $logDir . '/' . $file;
                // Пропускаем текущий лог и системные директории
                if ($file === '.' || $file === '..' || $file === $currentLog) {
                    continue;
                }
                
                // Если файл старше N дней - удаляем
                if (filemtime($filePath) < strtotime("-{$daysToKeep} days")) {
                    unlink($filePath);
                    $this->info("Удален старый лог файл: $file");
                }
            }
        }
    }

    // Метод для ротации логов при достижении определенного размера
    public function rotateLogIfNeeded($maxSizeMB = 10) {
        if (file_exists($this->logFile)) {
            $sizeInBytes = filesize($this->logFile);
            $maxSizeBytes = $maxSizeMB * 1024 * 1024;
            
            if ($sizeInBytes > $maxSizeBytes) {
                $newName = $this->logFile . '.' . date('Y-m-d_H-i-s') . '.old';
                rename($this->logFile, $newName);
                $this->info("Лог файл перемещен в: $newName");
                
                // Очищаем старые логи
                $this->cleanOldLogs();
            }
        }
    }
}
