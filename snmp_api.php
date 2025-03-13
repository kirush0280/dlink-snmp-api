<?php
require 'config.php';
require 'Logger.php';

class DlinkSNMP {
    private $ip;
    private $readOnlyCommunity;
    private $readWriteCommunity;
    private $portCount;
    private $maxBytes;
    private $logger;

    public function __construct($ip = null) {
        $this->logger = Logger::getInstance();
        
        if ($ip === null) {
            // Для эндпоинта help не требуется SNMP-инициализация
            return;
        }
        
        $this->logger->info("Инициализация DlinkSNMP для IP: $ip");
        
        $config = include 'config.php';
        $this->ip = $ip;
        $this->readOnlyCommunity = $config['snmp']['read_only_community'];
        $this->readWriteCommunity = $config['snmp']['read_write_community'];
        
        // Пропускаем проверку для вызова help
        if ($ip !== 'localhost') {
            try {
                // Проверяем read-only community
                $this->logger->debug("Проверка read-only community...");
                $this->checkSnmpCommunity($this->readOnlyCommunity, 'read-only');
                $this->logger->info("Read-only community работает корректно");
                
                // Проверяем read-write community
                $this->logger->debug("Проверка read-write community...");
                $this->checkSnmpCommunity($this->readWriteCommunity, 'read-write');
                $this->logger->info("Read-write community работает корректно");
                
                // Определяем количество портов при инициализации
                $this->portCount = $this->getPortCount();
                $this->logger->info("Определено количество портов: {$this->portCount}");
                
                // Вычисляем количество байт для маски на основе количества портов
                $this->maxBytes = ceil($this->portCount / 8);
                $this->logger->debug("Установлен размер маски: {$this->maxBytes} байт");
            } catch (Exception $e) {
                $this->logger->error("Ошибка инициализации SNMP: " . $e->getMessage());
                throw new Exception("Ошибка инициализации SNMP: " . $e->getMessage());
            }
        }
    }

    // Получение количества портов коммутатора
    private function getPortCount() {
        try {
            // Получаем общее количество интерфейсов
            $ifNumber = snmp2_get($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.1.0');
            if ($ifNumber === false) {
                throw new Exception("Не удалось получить количество портов");
            }

            // Преобразуем строку вида "INTEGER: 28" в число
            if (preg_match('/INTEGER: (\d+)/', $ifNumber, $matches)) {
                $totalPorts = (int)$matches[1];
                // Обычно первые два интерфейса - системные
                return $totalPorts - 2;
            }
            
            // Если не удалось определить, используем безопасное значение по умолчанию
            return 24;
        } catch (Exception $e) {
            // В случае ошибки используем безопасное значение по умолчанию
            return 24;
        }
    }

    // Создание маски портов с учетом реального количества портов
    private function createPortMask($portsStr) {
        $mask = array_fill(0, $this->maxBytes, '00');
        
        // Разбираем строку портов (например: "1-4" или "1,2,3,4" или "1-3,5")
        $parts = explode(',', $portsStr);
        foreach ($parts as $part) {
            if (strpos($part, '-') !== false) {
                list($start, $end) = explode('-', $part);
                if ($end > $this->portCount) {
                    throw new Exception("Порт {$end} выходит за пределы количества портов коммутатора ({$this->portCount})");
                }
                $ports = range($start, $end);
            } else {
                if ($part > $this->portCount) {
                    throw new Exception("Порт $part выходит за пределы количества портов коммутатора ({$this->portCount})");
                }
                $ports = [$part];
            }
            
            foreach ($ports as $port) {
                $byteIndex = floor(($port - 1) / 8);
                $bitInByte = 7 - (($port - 1) % 8);
                
                if ($byteIndex < $this->maxBytes) {
                    $currentByte = hexdec($mask[$byteIndex]);
                    $mask[$byteIndex] = sprintf("%02X", $currentByte | (1 << $bitInByte));
                }
            }
        }
        
        return $mask;
    }

    // Получение маски VLAN
    private function getVlanMask($vlanId, $type = 'tagged') {
        $oid = $type === 'tagged' ? 
            ".1.3.6.1.2.1.17.7.1.4.3.1.2.$vlanId" : 
            ".1.3.6.1.2.1.17.7.1.4.3.1.4.$vlanId";
            
        $result = snmp2_get($this->ip, $this->readOnlyCommunity, $oid);
        if ($result === false) {
            return null;
        }

        if (preg_match('/Hex-STRING: (.+)$/', $result, $matches)) {
            $hexMask = preg_replace('/\s+/', '', $matches[1]);
            return str_split($hexMask, 2);
        }
        return null;
    }

    // Получение подробной информации о VLAN'ах
    public function getVlanDetails() {
        $vlans = [];
        $result = snmp2_real_walk($this->ip, $this->readOnlyCommunity, ".1.3.6.1.2.1.17.7.1.4.3.1.1");
        
        if (is_array($result)) {
            foreach ($result as $oid => $value) {
                if (preg_match('/\.(\d+)$/', $oid, $matches)) {
                    $vlanId = $matches[1];
                    $vlanInfo = [
                        'id' => $vlanId,
                        'name' => preg_replace('/STRING: "(.*)"/', '$1', $value),
                        'ports' => [
                            'tagged' => [],
                            'untagged' => []
                        ]
                    ];
                    
                    // Получаем маски для tagged и untagged портов
                    $taggedMask = $this->getVlanMask($vlanId, 'tagged');
                    $untaggedMask = $this->getVlanMask($vlanId, 'untagged');
                    
                    // Анализируем маски и определяем порты
                    if ($taggedMask) {
                        for ($port = 1; $port <= $this->portCount; $port++) {
                            $byteIndex = floor(($port - 1) / 8);
                            $bitInByte = 7 - (($port - 1) % 8);
                            $bitMask = 1 << $bitInByte;
                            
                            if ($byteIndex < count($taggedMask)) {
                                if (hexdec($taggedMask[$byteIndex]) & $bitMask) {
                                    // Проверяем, не является ли порт untagged
                                    $isUntagged = false;
                                    if ($untaggedMask && $byteIndex < count($untaggedMask)) {
                                        if (hexdec($untaggedMask[$byteIndex]) & $bitMask) {
                                            $isUntagged = true;
                                        }
                                    }
                                    
                                    if (!$isUntagged) {
                                        $vlanInfo['ports']['tagged'][] = $port;
                                    }
                                }
                            }
                        }
                    }
                    
                    if ($untaggedMask) {
                        for ($port = 1; $port <= $this->portCount; $port++) {
                            $byteIndex = floor(($port - 1) / 8);
                            $bitInByte = 7 - (($port - 1) % 8);
                            $bitMask = 1 << $bitInByte;
                            
                            if ($byteIndex < count($untaggedMask)) {
                                if (hexdec($untaggedMask[$byteIndex]) & $bitMask) {
                                    $vlanInfo['ports']['untagged'][] = $port;
                                }
                            }
                        }
                    }
                    
                    $vlans[] = $vlanInfo;
                }
            }
        }
        
        return $vlans;
    }

    // Проверка существования VLAN
    private function checkVlanExists($vlanId) {
        $vlans = $this->getExistingVlans();
        return in_array($vlanId, $vlans);
    }

    // Логирование текущего состояния VLAN'ов
    private function logVlanState($operation) {
        $this->logger->info("=== Текущее состояние VLAN'ов перед операцией: $operation ===");
        
        // Получаем список всех VLAN'ов
        $vlans = $this->getVlanDetails();
        
        foreach ($vlans as $vlan) {
            $this->logger->info("VLAN {$vlan['id']} ({$vlan['name']})");
            $this->logger->info("  Tagged порты: " . (empty($vlan['ports']['tagged']) ? "нет" : implode(", ", $vlan['ports']['tagged'])));
            $this->logger->info("  Untagged порты: " . (empty($vlan['ports']['untagged']) ? "нет" : implode(", ", $vlan['ports']['untagged'])));
        }
        $this->logger->info("================================================");
    }

    private function validateVlanId($vlanId) {
        if (!is_numeric($vlanId)) {
            throw new Exception("VLAN ID должен быть числом");
        }
        
        $vlanId = intval($vlanId);
        if ($vlanId < 1 || $vlanId > 4094) {
            throw new Exception("VLAN ID должен быть в диапазоне от 1 до 4094");
        }
        
        return $vlanId;
    }

    private function validatePorts($portsStr) {
        $parts = explode(',', $portsStr);
        $allPorts = [];
        
        foreach ($parts as $part) {
            if (strpos($part, '-') !== false) {
                list($start, $end) = explode('-', $part);
                if (!is_numeric($start) || !is_numeric($end)) {
                    throw new Exception("Некорректный формат портов: $part");
                }
                if ($start > $end) {
                    throw new Exception("Начальный порт больше конечного: $part");
                }
                if ($start < 1 || $end > $this->portCount) {
                    throw new Exception("Порты должны быть в диапазоне от 1 до {$this->portCount}");
                }
                $allPorts = array_merge($allPorts, range($start, $end));
            } else {
                if (!is_numeric($part)) {
                    throw new Exception("Некорректный номер порта: $part");
                }
                $port = intval($part);
                if ($port < 1 || $port > $this->portCount) {
                    throw new Exception("Порт $port выходит за пределы диапазона (1-{$this->portCount})");
                }
                $allPorts[] = $port;
            }
        }
        
        return array_unique($allPorts);
    }

    private function handleSnmpError($operation, $details = '') {
        $error = error_get_last();
        $errorMessage = $error ? $error['message'] : 'Неизвестная ошибка';
        $this->logger->error("Ошибка SNMP при $operation: $errorMessage $details");
        throw new Exception("Ошибка SNMP при $operation: $errorMessage");
    }

    // Обновляем метод createVlan с новыми проверками
    public function createVlan($vlanId) {
        try {
            $vlanId = $this->validateVlanId($vlanId);
            $this->logVlanState("создание VLAN $vlanId");
            $this->logger->info("Попытка создания VLAN $vlanId");
            
            // Проверяем, не существует ли уже VLAN
            if ($this->checkVlanExists($vlanId)) {
                $this->logger->warning("VLAN $vlanId уже существует");
                throw new Exception("VLAN $vlanId уже существует");
            }

            // 1. Сначала создаем VLAN через dot1qVlanStaticRowStatus
            $this->logger->debug("Создание VLAN $vlanId через dot1qVlanStaticRowStatus");
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.5.$vlanId",
                              'i', 4); // createAndGo(4)
            
            if ($result === false) {
                $this->handleSnmpError("создании VLAN", "VLAN ID: $vlanId");
            }

            // Добавляем задержку для обработки операции коммутатором
            sleep(2);

            // 2. Проверяем, что VLAN был создан
            if (!$this->checkVlanExists($vlanId)) {
                $this->logger->error("VLAN $vlanId не был создан");
                throw new Exception("VLAN не был создан");
            }

            // 3. Устанавливаем имя VLAN
            $this->logger->debug("Установка имени VLAN $vlanId");
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.1.$vlanId",
                              's', "$vlanId");
            
            if ($result === false) {
                $this->logger->warning("Не удалось установить имя VLAN $vlanId, но VLAN был создан");
            }

            // 4. Проверяем финальное состояние VLAN
            $vlanDetails = $this->getVlanDetails();
            $vlanCreated = false;
            foreach ($vlanDetails as $vlan) {
                if ($vlan['id'] == $vlanId) {
                    $vlanCreated = true;
                    break;
                }
            }

            if (!$vlanCreated) {
                throw new Exception("VLAN не был успешно создан");
            }

            $this->logger->info("VLAN $vlanId успешно создан");
            return true;
        } catch (Exception $e) {
            $this->logger->error("Ошибка создания VLAN $vlanId: " . $e->getMessage());
            throw new Exception("Ошибка создания VLAN: " . $e->getMessage());
        }
    }

    // Удаление VLAN
    public function deleteVlan($vlanId) {
        try {
            $this->logVlanState("удаление VLAN $vlanId");
            $this->logger->info("Попытка удаления VLAN $vlanId");
            
            // Проверяем существование VLAN
            if (!$this->checkVlanExists($vlanId)) {
                $this->logger->warning("VLAN $vlanId не существует");
                throw new Exception("VLAN $vlanId не существует");
            }

            // Получаем информацию о VLAN
            $vlanDetails = $this->getVlanDetails();
            $vlanInfo = null;
            foreach ($vlanDetails as $vlan) {
                if ($vlan['id'] == $vlanId) {
                    $vlanInfo = $vlan;
                    break;
                }
            }

            if (!$vlanInfo) {
                $this->logger->error("Не удалось получить информацию о VLAN $vlanId");
                throw new Exception("Не удалось получить информацию о VLAN $vlanId");
            }

            // Проверяем, нет ли портов в VLAN
            if (!empty($vlanInfo['ports']['tagged']) || !empty($vlanInfo['ports']['untagged'])) {
                $this->logger->warning("VLAN $vlanId содержит порты. Сначала удалите все порты из VLAN");
                throw new Exception("VLAN $vlanId содержит порты. Сначала удалите все порты из VLAN.");
            }

            // Удаляем VLAN через dot1qVlanStaticRowStatus
            $this->logger->debug("Удаление VLAN $vlanId через dot1qVlanStaticRowStatus");
            $result = snmp2_set($this->ip, $this->readWriteCommunity,
                              ".1.3.6.1.2.1.17.7.1.4.3.1.5.$vlanId",
                              'i', 6); // destroy(6)
            
            if ($result === false) {
                $this->logger->error("Ошибка удаления VLAN $vlanId");
                throw new Exception("Ошибка удаления VLAN");
            }

            $this->logger->info("VLAN $vlanId успешно удален");
            return true;
        } catch (Exception $e) {
            $this->logger->error("Ошибка удаления VLAN $vlanId: " . $e->getMessage());
            throw new Exception("Ошибка удаления VLAN: " . $e->getMessage());
        }
    }

    // Получение информации о VLAN для порта
    public function getPortVlan($portsStr) {
        $result = [];
        $parts = explode(',', $portsStr);
        
        foreach ($parts as $part) {
            if (strpos($part, '-') !== false) {
                list($start, $end) = explode('-', $part);
                $ports = range($start, $end);
            } else {
                $ports = [$part];
            }

            foreach ($ports as $port) {
                $portInfo = [];
                $portInfo["port"] = $port;
                $portInfo["vlans"] = [];

                // Получаем список всех VLAN
                $vlanList = $this->getExistingVlans();
                
                foreach ($vlanList as $vlanId) {
                    $taggedMask = $this->getVlanMask($vlanId, 'tagged');
                    $untaggedMask = $this->getVlanMask($vlanId, 'untagged');
                    
                    if (!$taggedMask || !$untaggedMask) continue;

                    $byteIndex = floor(($port - 1) / 8);
                    $bitInByte = 7 - (($port - 1) % 8);
                    $bitMask = 1 << $bitInByte;

                    if ($byteIndex < count($untaggedMask)) {
                        if (hexdec($untaggedMask[$byteIndex]) & $bitMask) {
                            $portInfo["vlans"][] = [
                                "vlan" => $vlanId,
                                "type" => "untagged"
                            ];
                            continue;
                        }
                    }

                    if ($byteIndex < count($taggedMask)) {
                        if (hexdec($taggedMask[$byteIndex]) & $bitMask) {
                            $portInfo["vlans"][] = [
                                "vlan" => $vlanId,
                                "type" => "tagged"
                            ];
                        }
                    }
                }

                $result[] = $portInfo;
            }
        }

        return $result;
    }

    // Получение списка существующих VLAN
    private function getExistingVlans() {
        $vlans = [];
        $result = snmp2_real_walk($this->ip, $this->readOnlyCommunity, ".1.3.6.1.2.1.17.7.1.4.3.1.1");
        
        if (is_array($result)) {
            foreach ($result as $oid => $value) {
                if (preg_match('/\.(\d+)$/', $oid, $matches)) {
                    $vlans[] = $matches[1];
                }
            }
        }
        
        return $vlans;
    }

    // Обновляем метод addPortsToVlan с новыми проверками
    public function addPortsToVlan($portsStr, $vlanId, $tagged = false) {
        try {
            $vlanId = $this->validateVlanId($vlanId);
            $validatedPorts = $this->validatePorts($portsStr);
            
            if (!$this->checkVlanExists($vlanId)) {
                throw new Exception("VLAN $vlanId не существует");
            }

            $this->logVlanState("добавление портов " . implode(',', $validatedPorts) . " в VLAN $vlanId как " . ($tagged ? "tagged" : "untagged"));
            
            // Получаем текущие маски
            $currentTaggedMask = $this->getVlanMask($vlanId, 'tagged');
            $currentUntaggedMask = $this->getVlanMask($vlanId, 'untagged');
            
            if (!$currentTaggedMask || !$currentUntaggedMask) {
                throw new Exception("Не удалось получить текущие маски портов");
            }
            
            // Создаем маску для новых портов
            $newPortsMask = $this->createPortMask(implode(',', $validatedPorts));
            
            if ($tagged) {
                // Для tagged портов объединяем текущую маску с новой
                $taggedValues = array_map(function($current, $new) {
                    return sprintf("%02X", hexdec($current) | hexdec($new));
                }, $currentTaggedMask, $newPortsMask);
                
                $taggedValue = implode(" ", $taggedValues);
                $result = snmp2_set($this->ip, $this->readWriteCommunity, 
                                  ".1.3.6.1.2.1.17.7.1.4.3.1.2.$vlanId", 
                                  'x', $taggedValue);
                
                if ($result === false) {
                    $this->handleSnmpError("добавлении tagged портов", "VLAN ID: $vlanId, Порты: $portsStr");
                }
            } else {
                // Для untagged портов
                $untaggedValues = array_map(function($current, $new) {
                    return sprintf("%02X", hexdec($current) | hexdec($new));
                }, $currentUntaggedMask, $newPortsMask);
                
                $result = snmp2_set($this->ip, $this->readWriteCommunity,
                                  ".1.3.6.1.2.1.17.7.1.4.3.1.4.$vlanId",
                                  'x', implode(" ", $untaggedValues));
                
                if ($result === false) {
                    $this->handleSnmpError("добавлении untagged портов", "VLAN ID: $vlanId, Порты: $portsStr");
                }
            }
            
            return true;
        } catch (Exception $e) {
            $this->logger->error("Ошибка добавления портов в VLAN: " . $e->getMessage());
            throw new Exception("Ошибка добавления портов в VLAN: " . $e->getMessage());
        }
    }

    // Удаление портов из VLAN
    public function removePortsFromVlan($portsStr, $vlanId) {
        if (!$this->checkVlanExists($vlanId)) {
            throw new Exception("VLAN $vlanId не существует");
        }

        // Получаем текущие маски
        $taggedMask = $this->getVlanMask($vlanId, 'tagged');
        $untaggedMask = $this->getVlanMask($vlanId, 'untagged');
        
        // Создаем маску для портов
        $portMask = $this->createPortMask($portsStr);
        
        // Инвертируем маску портов
        $invertedMask = array_map(function($byte) {
            return sprintf("%02X", hexdec($byte) ^ 0xFF);
        }, $portMask);
        
        // Очищаем untagged конфигурацию
        $untaggedValues = array_map(function($current, $inverted) {
            return sprintf("%02X", hexdec($current) & hexdec($inverted));
        }, $untaggedMask, $invertedMask);
        
        $result = snmp2_set($this->ip, $this->readWriteCommunity,
                          ".1.3.6.1.2.1.17.7.1.4.3.1.4.$vlanId",
                          'x', implode(" ", $untaggedValues));
        
        if ($result === false) {
            throw new Exception("Ошибка удаления портов из VLAN (untagged)");
        }
        
        // Очищаем tagged конфигурацию
        $taggedValues = array_map(function($current, $inverted) {
            return sprintf("%02X", hexdec($current) & hexdec($inverted));
        }, $taggedMask, $invertedMask);
        
        $result = snmp2_set($this->ip, $this->readWriteCommunity,
                          ".1.3.6.1.2.1.17.7.1.4.3.1.2.$vlanId",
                          'x', implode(" ", $taggedValues));
        
        if ($result === false) {
            throw new Exception("Ошибка удаления портов из VLAN (tagged)");
        }
        
        return true;
    }

    // Добавляем метод для получения информации о коммутаторе
    public function getSwitchInfo() {
        $info = [
            'port_count' => $this->portCount,
            'max_bytes' => $this->maxBytes
        ];
        
        try {
            // Получаем информацию о модели
            $sysDescr = snmp2_get($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.1.1.0');
            if ($sysDescr !== false && preg_match('/STRING: "(.*)"/', $sysDescr, $matches)) {
                $info['model'] = $matches[1];
            }
            
            // Получаем имя коммутатора
            $sysName = snmp2_get($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.1.5.0');
            if ($sysName !== false && preg_match('/STRING: "(.*)"/', $sysName, $matches)) {
                $info['name'] = $matches[1];
            }
        } catch (Exception $e) {
            // Игнорируем ошибки при получении дополнительной информации
        }
        
        return $info;
    }

    // Получение информации об интерфейсах
    public function getInterfaces() {
        $interfaces = [];
        
        try {
            echo "DEBUG: Начинаем получение информации об интерфейсах\n";
            
            // Получаем описания интерфейсов
            echo "DEBUG: Пытаемся получить описания интерфейсов...\n";
            $ifDescr = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.2');
            if ($ifDescr === false) {
                echo "DEBUG: Ошибка получения описаний интерфейсов\n";
                throw new Exception("Ошибка получения описаний интерфейсов");
            }
            echo "DEBUG: Получено описаний интерфейсов: " . count($ifDescr) . "\n";
            
            // Получаем статус интерфейсов
            echo "\nDEBUG: Пытаемся получить статус интерфейсов...\n";
            $ifOperStatus = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.8');
            if ($ifOperStatus === false) {
                echo "DEBUG: Ошибка получения статуса интерфейсов\n";
                throw new Exception("Ошибка получения статуса интерфейсов");
            }
            echo "DEBUG: Получено статусов интерфейсов: " . count($ifOperStatus) . "\n";
            
            // Получаем скорость интерфейсов
            echo "\nDEBUG: Пытаемся получить скорость интерфейсов...\n";
            $ifSpeed = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.5');
            if ($ifSpeed === false) {
                echo "DEBUG: Ошибка получения скорости интерфейсов\n";
                throw new Exception("Ошибка получения скорости интерфейсов");
            }
            echo "DEBUG: Получено скоростей интерфейсов: " . count($ifSpeed) . "\n";
            
            // Получаем MAC-адреса интерфейсов
            echo "\nDEBUG: Пытаемся получить MAC-адреса интерфейсов...\n";
            $ifPhysAddress = snmp2_walk($this->ip, $this->readOnlyCommunity, '.1.3.6.1.2.1.2.2.1.6');
            if ($ifPhysAddress === false) {
                echo "DEBUG: Ошибка получения MAC-адресов интерфейсов\n";
                throw new Exception("Ошибка получения MAC-адресов интерфейсов");
            }
            echo "DEBUG: Получено MAC-адресов интерфейсов: " . count($ifPhysAddress) . "\n";
            
            echo "\nDEBUG: Начинаем обработку полученных данных...\n";
            
            // Обрабатываем каждый интерфейс
            for ($i = 0; $i < count($ifDescr); $i++) {
                echo "\nDEBUG: Обработка интерфейса с индексом: " . ($i + 1) . "\n";
                
                // Извлекаем описание
                $description = preg_replace('/^STRING: "(.+)"$/', '$1', $ifDescr[$i]);
                echo "DEBUG: Описание интерфейса: $description\n";
                
                $interface = [
                    'index' => $i + 1,
                    'description' => $description,
                    'type' => 'unknown'
                ];
                
                // Добавляем статус интерфейса
                if (isset($ifOperStatus[$i])) {
                    $status = preg_replace('/^INTEGER: (\d+)$/', '$1', $ifOperStatus[$i]);
                    $interface['status'] = $this->getInterfaceStatus((int)$status);
                    echo "DEBUG: Статус интерфейса: {$interface['status']}\n";
                }
                
                // Добавляем скорость интерфейса
                if (isset($ifSpeed[$i])) {
                    $speed = preg_replace('/^Gauge32: (\d+)$/', '$1', $ifSpeed[$i]);
                    $interface['speed'] = $this->formatSpeed((int)$speed);
                    echo "DEBUG: Скорость интерфейса: {$interface['speed']}\n";
                }
                
                // Добавляем MAC-адрес
                if (isset($ifPhysAddress[$i])) {
                    $mac = preg_replace('/^Hex-STRING: (.+)$/', '$1', $ifPhysAddress[$i]);
                    if ($mac !== '00 00 00 00 00 00') {
                        $interface['mac'] = trim($mac);
                        echo "DEBUG: MAC-адрес интерфейса: {$interface['mac']}\n";
                    }
                }
                
                // Определяем тип интерфейса
                $index = $i + 1;
                if ($index <= 24) {
                    $interface['type'] = 'physical';
                } elseif ($index <= 26) {
                    $interface['type'] = 'combo';
                } elseif (strpos($description, '802.1Q') === 0) {
                    $interface['type'] = 'vlan';
                } else {
                    $interface['type'] = 'system';
                }
                echo "DEBUG: Тип интерфейса: {$interface['type']}\n";
                
                $interfaces[] = $interface;
            }
            
            echo "\nDEBUG: Всего обработано интерфейсов: " . count($interfaces) . "\n";
            
        } catch (Exception $e) {
            echo "DEBUG: Произошла ошибка: " . $e->getMessage() . "\n";
            throw new Exception("Ошибка получения информации об интерфейсах: " . $e->getMessage());
        }
        
        return $interfaces;
    }

    // Вспомогательная функция для форматирования скорости
    private function formatSpeed($speedValue) {
        if ($speedValue <= 0) {
            return "Нет линка";
        }
        if ($speedValue >= 1000000000) {
            return round($speedValue / 1000000000, 1) . " Гбит/с";
        }
        if ($speedValue >= 1000000) {
            return round($speedValue / 1000000) . " Мбит/с";
        }
        return $speedValue . " бит/с";
    }

    // Вспомогательная функция для получения статуса интерфейса
    private function getInterfaceStatus($status) {
        $statuses = [
            1 => "UP",
            2 => "DOWN",
            3 => "TESTING",
            4 => "UNKNOWN",
            5 => "DORMANT",
            6 => "NOT PRESENT",
            7 => "LOWER LAYER DOWN"
        ];
        return isset($statuses[$status]) ? $statuses[$status] : "UNKNOWN";
    }

    public function getApiDocs() {
        $docs = [
            'description' => 'API для управления коммутаторами D-Link через SNMP',
            'version' => '1.0.0',
            'security' => [
                'description' => 'Проверка SNMP community строк',
                'checks' => [
                    'read_only' => [
                        'description' => 'Проверка read-only community через запрос sysDescr',
                        'oid' => '.1.3.6.1.2.1.1.1.0'
                    ],
                    'read_write' => [
                        'description' => 'Проверка read-write community через запрос и установку sysContact',
                        'oid' => '.1.3.6.1.2.1.1.4.0'
                    ]
                ],
                'error_handling' => [
                    'read_only_fail' => 'Ошибка проверки read-only community',
                    'read_write_fail_read' => 'Ошибка проверки read-write community (чтение)',
                    'read_write_fail_write' => 'Ошибка проверки read-write community (запись)'
                ]
            ],
            'endpoints' => [
                'vlans' => [
                    'description' => 'Получение списка VLAN с подробной информацией',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> vlans',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'vlans'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/vlans?ip=<ip>',
                            'example' => '/snmp_api.php/vlans?ip=10.2.0.65'
                        ]
                    ],
                    'returns' => [
                        'vlan_id' => 'Идентификатор VLAN',
                        'name' => 'Имя VLAN',
                        'ports' => [
                            'tagged' => 'Список портов с тегированным трафиком',
                            'untagged' => 'Список портов с нетегированным трафиком'
                        ]
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 vlans',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"vlans"}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/vlans?ip=10.2.0.65'
                    ]
                ],
                'create' => [
                    'description' => 'Создание нового VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> create <vlan_id>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'create',
                                'vlan' => 'integer (номер VLAN)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/create?ip=<ip>&vlan=<vlan>',
                            'example' => '/snmp_api.php/create?ip=10.2.0.65&vlan=100'
                        ]
                    ],
                    'returns' => [
                        'success' => 'true/false',
                        'message' => 'Сообщение об успехе или ошибке'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 create 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"create","vlan":100}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/create?ip=10.2.0.65&vlan=100'
                    ]
                ],
                'delete' => [
                    'description' => 'Удаление VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> delete <vlan_id>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'delete',
                                'vlan' => 'integer (номер VLAN)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/delete?ip=<ip>&vlan=<vlan>',
                            'example' => '/snmp_api.php/delete?ip=10.2.0.65&vlan=100'
                        ]
                    ],
                    'returns' => [
                        'success' => 'true/false',
                        'message' => 'Сообщение об успехе или ошибке'
                    ],
                    'notes' => [
                        'Перед удалением VLAN необходимо удалить все порты из него',
                        'Если в VLAN есть порты, операция удаления будет отклонена'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 delete 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"delete","vlan":100}\' http://localhost:8000/snmp_api.php',
                        'browser' => 'http://localhost:8000/snmp_api.php/delete?ip=10.2.0.65&vlan=100'
                    ]
                ],
                'info' => [
                    'description' => 'Получение информации о коммутаторе',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> info',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'info'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/info?ip=<ip>',
                            'example' => '/snmp_api.php/info?ip=10.2.0.65'
                        ]
                    ],
                    'returns' => [
                        'name' => 'Имя коммутатора',
                        'model' => 'Модель коммутатора',
                        'port_count' => 'Количество портов',
                        'max_bytes' => 'Размер маски в байтах'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 info',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"info"}\' /snmp_api.php',
                        'browser' => '/snmp_api.php/info?ip=10.2.0.65'
                    ]
                ],
                'get' => [
                    'description' => 'Получение информации о VLAN на портах',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> get <ports>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'get',
                                'ports' => 'string (номера портов, например: "1-4" или "1,2,3,4")'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/get?ip=<ip>&ports=<ports>',
                            'example' => '/snmp_api.php/get?ip=10.2.0.65&ports=1-4'
                        ]
                    ],
                    'returns' => 'Список VLAN для каждого порта с указанием типа (tagged/untagged)',
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 get 1-4',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"get","ports":"1-4"}\' /snmp_api.php',
                        'browser' => '/snmp_api.php/get?ip=10.2.0.65&ports=1-4'
                    ]
                ],
                'add' => [
                    'description' => 'Добавление портов в VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> add <ports> <vlan> [tagged]',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'add',
                                'ports' => 'string (номера портов)',
                                'vlan' => 'integer (номер VLAN)',
                                'tagged' => 'boolean (опционально, по умолчанию false)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/add?ip=<ip>&ports=<ports>&vlan=<vlan>&tagged=<tagged>',
                            'example' => '/snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=0'
                        ]
                    ],
                    'notes' => 'Параметр tagged определяет тип добавления порта в VLAN (true - tagged, false - untagged)',
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 add 1-4 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"add","ports":"1-4","vlan":100,"tagged":false}\' /snmp_api.php',
                        'browser' => '/snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=0'
                    ]
                ],
                'remove' => [
                    'description' => 'Удаление портов из VLAN',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> remove <ports> <vlan>',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'remove',
                                'ports' => 'string (номера портов)',
                                'vlan' => 'integer (номер VLAN)'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/remove?ip=<ip>&ports=<ports>&vlan=<vlan>',
                            'example' => '/snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100'
                        ]
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 remove 1-4 100',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"remove","ports":"1-4","vlan":100}\' /snmp_api.php',
                        'browser' => '/snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100'
                    ]
                ],
                'interfaces' => [
                    'description' => 'Получение информации об интерфейсах коммутатора',
                    'usage' => [
                        'cli' => 'php snmp_api.php <ip> interfaces',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'ip' => 'string (IP-адрес коммутатора)',
                                'action' => 'interfaces'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/interfaces?ip=<ip>',
                            'example' => '/snmp_api.php/interfaces?ip=10.2.0.65'
                        ]
                    ],
                    'returns' => [
                        'Физические порты' => 'Список физических портов с их статусом и скоростью',
                        'VLAN интерфейсы' => 'Список VLAN интерфейсов',
                        'Системные интерфейсы' => 'Список системных интерфейсов'
                    ],
                    'examples' => [
                        'cli' => 'php snmp_api.php 10.2.0.65 interfaces',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"ip":"10.2.0.65","action":"interfaces"}\' /snmp_api.php',
                        'browser' => '/snmp_api.php/interfaces?ip=10.2.0.65'
                    ]
                ],
                'help' => [
                    'description' => 'Получение документации по API',
                    'usage' => [
                        'cli' => 'php snmp_api.php help',
                        'http' => [
                            'method' => 'POST',
                            'endpoint' => '/',
                            'body' => [
                                'action' => 'help'
                            ]
                        ],
                        'get' => [
                            'url' => '/snmp_api.php/help',
                            'example' => '/snmp_api.php/help'
                        ]
                    ],
                    'returns' => 'Полная документация по API',
                    'examples' => [
                        'cli' => 'php snmp_api.php help',
                        'curl' => 'curl -X POST -H "Content-Type: application/json" -d \'{"action":"help"}\' /snmp_api.php',
                        'browser' => '/snmp_api.php/help'
                    ]
                ]
            ]
        ];

        if (php_sapi_name() === 'cli') {
            return $this->formatCliDocs($docs);
        }
        
        return $docs;
    }

    private function formatCliDocs($docs, $indent = 0) {
        $output = "";
        $pad = str_repeat(" ", $indent);
        
        foreach ($docs as $key => $value) {
            if (is_array($value)) {
                $output .= "$pad$key:\n";
                $output .= $this->formatCliDocs($value, $indent + 2);
            } else {
                $output .= "$pad$key: $value\n";
            }
        }
        
        return $output;
    }

    private function checkSnmpCommunity($community, $type = 'read-only') {
        try {
            // Проверяем доступность коммутатора через sysDescr (для read-only)
            if ($type === 'read-only') {
                $result = snmp2_get($this->ip, $community, '.1.3.6.1.2.1.1.1.0');
                if ($result === false) {
                    throw new Exception("Ошибка проверки read-only community");
                }
            } else {
                // Для read-write пробуем получить и установить sysName
                $currentName = snmp2_get($this->ip, $community, '.1.3.6.1.2.1.1.5.0');
                if ($currentName === false) {
                    throw new Exception("Ошибка проверки read-write community (чтение)");
                }
                
                // Извлекаем текущее имя из строки вида 'STRING: "name"'
                if (preg_match('/STRING: "(.*)"/', $currentName, $matches)) {
                    $currentName = $matches[1];
                }
                
                // Пробуем установить то же самое значение обратно
                $result = snmp2_set($this->ip, $community, '.1.3.6.1.2.1.1.5.0', 's', $currentName);
                if ($result === false) {
                    throw new Exception("Ошибка проверки read-write community (запись)");
                }
            }
            
            return true;
        } catch (Exception $e) {
            throw new Exception("Ошибка проверки " . $type . " community: " . $e->getMessage());
        }
    }
}

// Обновляем CLI интерфейс
if (php_sapi_name() === 'cli') {
    $logger = Logger::getInstance();
    $logger->info("Запуск CLI интерфейса");
    
    if ($argc < 2) {
        $logger->warning("Недостаточно аргументов командной строки");
        die("Использование: php snmp_api.php <ip> <action> [ports] [vlan] [tagged]\n" .
            "Для получения полной документации используйте: php snmp_api.php help\n\n" .
            "Примечание: При каждом обращении к коммутатору выполняется автоматическая проверка\n" .
            "доступности и корректности SNMP community строк.\n");
    }

    try {
        if ($argv[1] === 'help') {
            $logger->info("Запрошена справка");
            $snmp = new DlinkSNMP();
            echo $snmp->getApiDocs();
            exit(0);
        }

        $ip = $argv[1];
        $action = $argv[2];
        
        $logger->info("Выполнение команды: $action для IP: $ip");
        
        // Специальная обработка для команд create и delete
        if (($action === 'create' || $action === 'delete') && isset($argv[3])) {
            $vlan = intval($argv[3]);
            $ports = null;
        } else {
            $ports = isset($argv[3]) ? $argv[3] : null;
            $vlan = isset($argv[4]) ? intval($argv[4]) : null;
        }
        
        $tagged = isset($argv[5]) ? (bool)$argv[5] : false;

        $logger->debug("Параметры команды: IP=$ip, Action=$action, Ports=" . ($ports ?? 'null') . 
                      ", VLAN=" . ($vlan ?? 'null') . ", Tagged=" . ($tagged ? 'true' : 'false'));

        $snmp = new DlinkSNMP($ip);
        
        switch ($action) {
            case 'info':
                $info = $snmp->getSwitchInfo();
                echo "=== Информация о коммутаторе ===\n";
                if (isset($info['name'])) echo "Имя: {$info['name']}\n";
                if (isset($info['model'])) echo "Модель: {$info['model']}\n";
                echo "Количество портов: {$info['port_count']}\n";
                echo "Размер маски (байт): {$info['max_bytes']}\n";
                break;

            case 'get':
                if (!$ports) {
                    die("Необходимо указать порты\n");
                }
                $result = $snmp->getPortVlan($ports);
                foreach ($result as $portInfo) {
                    echo "=== Порт {$portInfo['port']} ===\n";
                    if (empty($portInfo['vlans'])) {
                        echo "Порт {$portInfo['port']} не найден ни в одном VLAN\n";
                    } else {
                        foreach ($portInfo['vlans'] as $vlanInfo) {
                            echo "Порт {$portInfo['port']} находится в VLAN {$vlanInfo['vlan']} ({$vlanInfo['type']})\n";
                        }
                    }
                }
                break;

            case 'add':
                if ($vlan === null) {
                    die("Для добавления портов необходимо указать VLAN\n" .
                        "Использование: php snmp_api.php <ip> add <ports> <vlan> [tagged]\n");
                }
                $result = $snmp->addPortsToVlan($ports, $vlan, $tagged);
                echo "Порты $ports успешно добавлены в VLAN $vlan как " . ($tagged ? "tagged" : "untagged") . "\n";
                break;

            case 'remove':
                if ($vlan === null) {
                    die("Для удаления портов необходимо указать VLAN\n" .
                        "Использование: php snmp_api.php <ip> remove <ports> <vlan>\n");
                }
                $result = $snmp->removePortsFromVlan($ports, $vlan);
                echo "Порты $ports успешно удалены из VLAN $vlan\n";
                break;

            case 'create':
                if ($vlan === null) {
                    die("Для создания VLAN необходимо указать ID\n" .
                        "Использование: php snmp_api.php <ip> create <vlan_id>\n");
                }
                $result = $snmp->createVlan($vlan);
                echo "VLAN $vlan успешно создан\n";
                break;

            case 'delete':
                echo "DEBUG: Вход в case 'delete'\n";
                echo "DEBUG: vlan = " . ($vlan ?? 'null') . "\n";
                if ($vlan === null) {
                    die("Для удаления VLAN необходимо указать ID\n" .
                        "Использование: php snmp_api.php <ip> delete <vlan_id>\n");
                }
                $result = $snmp->deleteVlan($vlan);
                echo "VLAN $vlan успешно удален\n";
                break;

            case 'vlans':
                $vlans = $snmp->getVlanDetails();
                echo "=== Список VLAN'ов ===\n";
                foreach ($vlans as $vlan) {
                    echo "\nVLAN {$vlan['id']} ({$vlan['name']})\n";
                    echo "Tagged порты: " . (empty($vlan['ports']['tagged']) ? "нет" : implode(", ", $vlan['ports']['tagged'])) . "\n";
                    echo "Untagged порты: " . (empty($vlan['ports']['untagged']) ? "нет" : implode(", ", $vlan['ports']['untagged'])) . "\n";
                }
                break;

            case 'interfaces':
                $interfaces = $snmp->getInterfaces();
                echo "=== Интерфейсы коммутатора ===\n\n";
                
                echo "Физические порты:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'physical' || $interface['type'] === 'combo') {
                        $portType = $interface['type'] === 'physical' ? "Медный порт" : "Combo порт";
                        echo "Порт {$interface['index']} ($portType)\n";
                        echo "Описание: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['speed'])) {
                            echo "Скорость: {$interface['speed']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nVLAN интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'vlan') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nСистемные интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'system') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                break;

            case 'update':
                try {
                    // Создаем временную директорию
                    $tempDir = sys_get_temp_dir() . '/dlink-snmp-api-update-' . uniqid();
                    mkdir($tempDir);
                    
                    // Клонируем репозиторий во временную директорию
                    exec("git clone https://github.com/kirush0280/dlink-snmp-api.git $tempDir 2>&1", $output, $returnVar);
                    
                    if ($returnVar !== 0) {
                        throw new Exception("Ошибка клонирования репозитория: " . implode("\n", $output));
                    }
                    
                    // Сохраняем текущий config.php
                    $currentConfig = file_get_contents('config.php');
                    
                    // Копируем файлы из временной директории
                    $files = [
                        'snmp_api.php',
                        'Logger.php',
                        'README.md'
                    ];
                    
                    foreach ($files as $file) {
                        if (file_exists($tempDir . '/' . $file)) {
                            copy($tempDir . '/' . $file, $file);
                        }
                    }
                    
                    // Восстанавливаем config.php
                    file_put_contents('config.php', $currentConfig);
                    
                    // Удаляем временную директорию
                    array_map('unlink', glob("$tempDir/*.*"));
                    rmdir($tempDir);
                    
                    echo json_encode([
                        'success' => true,
                        'message' => 'Скрипт успешно обновлен'
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    exit;
                    
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode([
                        'success' => false,
                        'error' => $e->getMessage()
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    exit;
                }
                break;

            case 'help':
                $snmp = new DlinkSNMP();
                $docs = $snmp->getApiDocs();
                echo json_encode([
                    'success' => true,
                    'data' => $docs
                ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                break;

            default:
                die("Неизвестное действие: $action\n");
        }
    } catch (Exception $e) {
        die("Ошибка: " . $e->getMessage() . "\n");
    }
    exit(0);
}

// Обновляем HTTP интерфейс
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    
    try {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['action'])) {
            throw new Exception("Необходимо указать действие");
        }

        // Специальная обработка для help и update
        if ($input['action'] === 'help' || $input['action'] === 'update') {
            if ($input['action'] === 'help') {
                $snmp = new DlinkSNMP();
                $docs = $snmp->getApiDocs();
                echo json_encode([
                    'success' => true,
                    'data' => $docs
                ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                exit;
            }
            // ... остальной код для update
        }
        
        // Для всех остальных действий требуется IP
        if (!isset($input['ip'])) {
            throw new Exception("Необходимо указать IP-адрес");
        }
        
        $snmp = new DlinkSNMP($input['ip']);
        $result = null;
        
        switch ($input['action']) {
            case 'info':
                $info = $snmp->getSwitchInfo();
                echo json_encode([
                    'success' => true,
                    'data' => $info
                ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                break;

            case 'get':
                if (!isset($input['ports'])) {
                    throw new Exception("Необходимо указать порты");
                }
                $result = $snmp->getPortVlan($input['ports']);
                break;
                
            case 'add':
                if (!isset($input['ports']) || !isset($input['vlan'])) {
                    throw new Exception("Необходимо указать порты и VLAN");
                }
                $tagged = isset($input['tagged']) ? $input['tagged'] : false;
                $result = $snmp->addPortsToVlan($input['ports'], $input['vlan'], $tagged);
                break;
                
            case 'remove':
                if (!isset($input['ports']) || !isset($input['vlan'])) {
                    throw new Exception("Необходимо указать порты и VLAN");
                }
                $result = $snmp->removePortsFromVlan($input['ports'], $input['vlan']);
                break;
                
            case 'interfaces':
                $interfaces = $snmp->getInterfaces();
                echo "=== Интерфейсы коммутатора ===\n\n";
                
                echo "Физические порты:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'physical' || $interface['type'] === 'combo') {
                        $portType = $interface['type'] === 'physical' ? "Медный порт" : "Combo порт";
                        echo "Порт {$interface['index']} ($portType)\n";
                        echo "Описание: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['speed'])) {
                            echo "Скорость: {$interface['speed']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nVLAN интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'vlan') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                
                echo "\nСистемные интерфейсы:\n";
                echo "----------------\n";
                foreach ($interfaces as $interface) {
                    if ($interface['type'] === 'system') {
                        echo "Интерфейс: {$interface['description']}\n";
                        if (isset($interface['status'])) {
                            echo "Статус: {$interface['status']}\n";
                        }
                        if (isset($interface['mac'])) {
                            echo "MAC: {$interface['mac']}\n";
                        }
                        echo "----------------\n";
                    }
                }
                break;
                
            case 'create':
                if (!isset($input['vlan'])) {
                    throw new Exception("Необходимо указать ID VLAN");
                }
                $result = $snmp->createVlan($input['vlan']);
                break;
                
            case 'delete':
                echo "DEBUG: Вход в case 'delete'\n";
                echo "DEBUG: vlan = " . ($input['vlan'] ?? 'null') . "\n";
                if ($input['vlan'] === null) {
                    throw new Exception("Необходимо указать ID VLAN");
                }
                $result = $snmp->deleteVlan($input['vlan']);
                echo "VLAN " . $input['vlan'] . " успешно удален\n";
                break;

            case 'vlans':
                $result = $snmp->getVlanDetails();
                break;

            case 'update':
                try {
                    // Создаем временную директорию
                    $tempDir = sys_get_temp_dir() . '/dlink-snmp-api-update-' . uniqid();
                    mkdir($tempDir);
                    
                    // Клонируем репозиторий во временную директорию
                    exec("git clone https://github.com/kirush0280/dlink-snmp-api.git $tempDir 2>&1", $output, $returnVar);
                    
                    if ($returnVar !== 0) {
                        throw new Exception("Ошибка клонирования репозитория: " . implode("\n", $output));
                    }
                    
                    // Сохраняем текущий config.php
                    $currentConfig = file_get_contents('config.php');
                    
                    // Копируем файлы из временной директории
                    $files = [
                        'snmp_api.php',
                        'Logger.php',
                        'README.md'
                    ];
                    
                    foreach ($files as $file) {
                        if (file_exists($tempDir . '/' . $file)) {
                            copy($tempDir . '/' . $file, $file);
                        }
                    }
                    
                    // Восстанавливаем config.php
                    file_put_contents('config.php', $currentConfig);
                    
                    // Удаляем временную директорию
                    array_map('unlink', glob("$tempDir/*.*"));
                    rmdir($tempDir);
                    
                    echo json_encode([
                        'success' => true,
                        'message' => 'Скрипт успешно обновлен'
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    exit;
                    
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode([
                        'success' => false,
                        'error' => $e->getMessage()
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    exit;
                }
                break;

            case 'help':
                $snmp = new DlinkSNMP();
                $docs = $snmp->getApiDocs();
                echo json_encode([
                    'success' => true,
                    'data' => $docs
                ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                break;

            default:
                throw new Exception("Неизвестное действие");
        }
        
        echo json_encode([
            'success' => true,
            'data' => $result
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Парсим URL для получения команды
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $pathParts = explode('/', trim($path, '/'));
    $scriptParts = explode('/', $_SERVER['SCRIPT_NAME']);
    $baseScript = end($scriptParts);
    
    // Если запрос к корню - показываем HTML интерфейс
    if (count($pathParts) <= 1 || end($pathParts) === $baseScript) {
        header('Content-Type: text/html; charset=utf-8');
        // Используем HEREDOC для большого HTML блока
        echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>D-Link SNMP API</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        .endpoint { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; }
        .method { color: #666; }
        .url { color: #007bff; }
        .description { margin: 10px 0; }
        .params { margin-left: 20px; }
        .try-it { margin-top: 10px; }
        input, select { margin: 5px; padding: 5px; }
        button { padding: 5px 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result-section {
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            min-height: 100px;
            display: none;
            position: relative;
        }
        .result-section.active {
            display: block;
        }
        .result-section pre {
            margin: 0;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 14px;
            color: #333;
        }
        .result-section.error {
            background: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        .result-section.success {
            background: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }
        .close-button {
            position: absolute;
            top: 10px;
            right: 10px;
            width: 24px;
            height: 24px;
            background: #dc3545;
            color: white;
            border: none;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            line-height: 1;
            padding: 0;
        }
        .close-button:hover {
            background: #c82333;
        }
        .examples {
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .examples h4 {
            margin: 0 0 10px 0;
            color: #666;
        }
        .tab-container {
            margin-bottom: 10px;
        }
        .tab-buttons {
            display: flex;
            gap: 2px;
            margin-bottom: 10px;
        }
        .tab-button {
            padding: 8px 16px;
            background: #e9ecef;
            border: none;
            cursor: pointer;
            border-radius: 4px 4px 0 0;
            font-size: 14px;
        }
        .tab-button:hover {
            background: #dee2e6;
        }
        .tab-button.active {
            background: #007bff;
            color: white;
        }
        .tab-content {
            display: none;
            padding: 15px;
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 0 0 4px 4px;
        }
        .tab-content.active {
            display: block;
        }
        .tab-content pre {
            margin: 0;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 14px;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            color: #333;
        }
        .returns {
            margin: 10px 0;
            padding: 10px;
            background: #e9ecef;
            border-radius: 4px;
        }
        .returns h4 {
            margin: 0 0 10px 0;
            color: #666;
        }
        .returns pre {
            margin: 0;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 14px;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            color: #333;
        }
        .notes {
            margin: 10px 0;
            padding: 10px;
            background: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 4px;
        }
        .notes p {
            margin: 5px 0;
            color: #856404;
        }
        .notes strong {
            color: #533f03;
        }
        .update-section {
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }
        .update-button {
            background: #28a745;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .update-button:hover {
            background: #218838;
        }
        #update-status {
            margin-top: 10px;
            padding: 10px;
            border-radius: 4px;
            display: none;
        }
        .update-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .update-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
    <script>
        function tryEndpoint(action) {
            const resultDiv = document.getElementById("result");
            resultDiv.style.display = 'block';
            resultDiv.className = 'result-section';
            resultDiv.innerHTML = '<button class="close-button" onclick="closeResult()">&times;</button><div style="text-align: center; padding: 20px;">Выполняется запрос...</div>';
            
            const ip = document.getElementById('ip-' + action)?.value;
            let url = window.location.pathname + '/' + action + '?ip=' + encodeURIComponent(ip);
            
            if (action === "get" || action === "add" || action === "remove") {
                const ports = document.getElementById('ports-' + action)?.value;
                if (ports) {
                    url += '&ports=' + encodeURIComponent(ports);
                }
            }
            
            if (action === "add" || action === "remove" || action === "create" || action === "delete") {
                const vlan = document.getElementById('vlan-' + action)?.value;
                if (vlan) {
                    url += '&vlan=' + encodeURIComponent(vlan);
                }
            }
            
            if (action === "add") {
                const tagged = document.getElementById("tagged-add")?.value;
                if (tagged) {
                    url += '&tagged=' + encodeURIComponent(tagged);
                }
            }
            
            fetch(url)
                .then(response => {
                    const contentType = response.headers.get('content-type');
                    if (contentType && contentType.includes('application/json')) {
                        return response.json();
                    }
                    return response.text().then(text => {
                        throw new Error('Получен неверный формат ответа: ' + text);
                    });
                })
                .then(data => {
                    resultDiv.className = 'result-section ' + (data.success ? 'success' : 'error');
                    resultDiv.innerHTML = '<button class="close-button" onclick="closeResult()">&times;</button><pre>' + JSON.stringify(data, null, 2) + '</pre>';
                })
                .catch(err => {
                    resultDiv.className = 'result-section error';
                    resultDiv.innerHTML = '<button class="close-button" onclick="closeResult()">&times;</button><pre>Ошибка: ' + (err.message || "Неизвестная ошибка") + '</pre>';
                });
        }

        function closeResult() {
            const resultDiv = document.getElementById("result");
            resultDiv.style.display = 'none';
        }

        function showTab(button, tabId) {
            const tabContainer = button.closest('.tab-container');
            tabContainer.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            tabContainer.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            button.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        function updateFromGitHub() {
            const statusDiv = document.getElementById('update-status');
            statusDiv.style.display = 'block';
            statusDiv.className = '';
            statusDiv.textContent = 'Обновление...';
            
            fetch(window.location.pathname + '/update')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        statusDiv.className = 'update-success';
                        statusDiv.textContent = 'Скрипт успешно обновлен!';
                        setTimeout(() => {
                            window.location.reload();
                        }, 2000);
                    } else {
                        statusDiv.className = 'update-error';
                        statusDiv.textContent = 'Ошибка обновления: ' + data.error;
                    }
                })
                .catch(err => {
                    statusDiv.className = 'update-error';
                    statusDiv.textContent = 'Ошибка при обновлении: ' + err.message;
                });
        }
    </script>
</head>
<body>
    <div class="container">
        <!-- Перемещаем блок с результатами вверх -->
        <div class="result-section" id="result" style="position: sticky; top: 20px; z-index: 100; margin-bottom: 20px;">
            <button class="close-button" onclick="closeResult()">&times;</button>
        </div>
        
        <div class="endpoint">
            <h3 class="method">Получить информацию о коммутаторе</h3>
            <div class="description">
                Получает основную информацию о коммутаторе: модель, имя, количество портов.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'info-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'info-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'info-browser')">Browser</button>
                    </div>
                    <div id="info-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 info</pre>
                    </div>
                    <div id="info-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"info"}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="info-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/info?ip=10.2.0.65</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-info" placeholder="IP-адрес коммутатора">
                <button type="button" class="execute-btn" onclick="tryEndpoint('info')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Получить информацию о VLAN на портах</h3>
            <div class="description">
                Получает информацию о VLAN-конфигурации для указанных портов.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'get-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'get-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'get-browser')">Browser</button>
                    </div>
                    <div id="get-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 get 1-4</pre>
                    </div>
                    <div id="get-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"get","ports":"1-4"}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="get-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/get?ip=10.2.0.65&ports=1-4</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-get" placeholder="IP-адрес коммутатора">
                <input type="text" id="ports-get" placeholder="Порты (например: 1-4)">
                <button type="button" class="execute-btn" onclick="tryEndpoint('get')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Добавить порты в VLAN</h3>
            <div class="description">
                Добавляет указанные порты в VLAN как tagged или untagged.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'add-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'add-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'add-browser')">Browser</button>
                    </div>
                    <div id="add-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 add 1-4 100 1</pre>
                    </div>
                    <div id="add-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"add","ports":"1-4","vlan":100,"tagged":true}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="add-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/add?ip=10.2.0.65&ports=1-4&vlan=100&tagged=1</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-add" placeholder="IP-адрес коммутатора">
                <input type="text" id="ports-add" placeholder="Порты">
                <input type="number" id="vlan-add" placeholder="VLAN ID">
                <select id="tagged-add">
                    <option value="0">Untagged</option>
                    <option value="1">Tagged</option>
                </select>
                <button type="button" class="execute-btn" onclick="tryEndpoint('add')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Удалить порты из VLAN</h3>
            <div class="description">
                Удаляет указанные порты из VLAN.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'remove-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'remove-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'remove-browser')">Browser</button>
                    </div>
                    <div id="remove-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 remove 1-4 100</pre>
                    </div>
                    <div id="remove-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"remove","ports":"1-4","vlan":100}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="remove-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/remove?ip=10.2.0.65&ports=1-4&vlan=100</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-remove" placeholder="IP-адрес коммутатора">
                <input type="text" id="ports-remove" placeholder="Порты">
                <input type="number" id="vlan-remove" placeholder="VLAN ID">
                <button type="button" class="execute-btn" onclick="tryEndpoint('remove')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Создать VLAN</h3>
            <div class="description">
                Создает новый VLAN с указанным ID.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'create-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'create-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'create-browser')">Browser</button>
                    </div>
                    <div id="create-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 create 100</pre>
                    </div>
                    <div id="create-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"create","vlan":100}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="create-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/create?ip=10.2.0.65&vlan=100</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-create" placeholder="IP-адрес коммутатора">
                <input type="number" id="vlan-create" placeholder="VLAN ID">
                <button type="button" class="execute-btn" onclick="tryEndpoint('create')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Удалить VLAN</h3>
            <div class="description">
                Удаляет существующий VLAN. Перед удалением необходимо удалить все порты из VLAN.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'delete-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'delete-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'delete-browser')">Browser</button>
                    </div>
                    <div id="delete-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 delete 100</pre>
                    </div>
                    <div id="delete-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"delete","vlan":100}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="delete-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/delete?ip=10.2.0.65&vlan=100</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-delete" placeholder="IP-адрес коммутатора">
                <input type="number" id="vlan-delete" placeholder="VLAN ID">
                <button type="button" class="execute-btn" onclick="tryEndpoint('delete')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Получить список VLAN'ов</h3>
            <div class="description">
                Получает полный список всех VLAN'ов на коммутаторе с информацией о портах.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'vlans-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'vlans-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'vlans-browser')">Browser</button>
                    </div>
                    <div id="vlans-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 vlans</pre>
                    </div>
                    <div id="vlans-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"vlans"}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="vlans-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/vlans?ip=10.2.0.65</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-vlans" placeholder="IP-адрес коммутатора">
                <button type="button" class="execute-btn" onclick="tryEndpoint('vlans')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Получить информацию об интерфейсах</h3>
            <div class="description">
                Получает подробную информацию о всех интерфейсах коммутатора, включая физические порты, VLAN интерфейсы и системные интерфейсы.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'interfaces-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'interfaces-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'interfaces-browser')">Browser</button>
                    </div>
                    <div id="interfaces-cli" class="tab-content active">
                        <pre>php snmp_api.php 10.2.0.65 interfaces</pre>
                    </div>
                    <div id="interfaces-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"ip":"10.2.0.65","action":"interfaces"}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="interfaces-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/interfaces?ip=10.2.0.65</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <input type="text" id="ip-interfaces" placeholder="IP-адрес коммутатора">
                <button type="button" class="execute-btn" onclick="tryEndpoint('interfaces')">Выполнить</button>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Обновить скрипт</h3>
            <div class="description">
                Обновляет скрипт до последней версии из GitHub репозитория.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'update-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'update-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'update-browser')">Browser</button>
                    </div>
                    <div id="update-cli" class="tab-content active">
                        <pre>php snmp_api.php update</pre>
                    </div>
                    <div id="update-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"action":"update"}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="update-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/update</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <button type="button" class="update-button" onclick="updateFromGitHub()">Обновить скрипт</button>
                <div id="update-status"></div>
            </div>
        </div>

        <div class="endpoint">
            <h3 class="method">Получить справку</h3>
            <div class="description">
                Получает полную документацию по API с описанием всех доступных команд и примерами использования.
            </div>
            <div class="examples">
                <h4>Примеры:</h4>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab(this, 'help-cli')">CLI</button>
                        <button class="tab-button" onclick="showTab(this, 'help-curl')">CURL</button>
                        <button class="tab-button" onclick="showTab(this, 'help-browser')">Browser</button>
                    </div>
                    <div id="help-cli" class="tab-content active">
                        <pre>php snmp_api.php help</pre>
                    </div>
                    <div id="help-curl" class="tab-content">
                        <pre>curl -X POST -H "Content-Type: application/json" -d '{"action":"help"}' http://localhost/dlink-snmp-api/snmp_api.php</pre>
                    </div>
                    <div id="help-browser" class="tab-content">
                        <pre>http://localhost/dlink-snmp-api/snmp_api.php/help</pre>
                    </div>
                </div>
            </div>
            <div class="try-it">
                <button type="button" class="execute-btn" onclick="tryEndpoint('help')">Получить справку</button>
            </div>
        </div>
    </div>
</body>
</html>
HTML;
    } else {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $action = end($pathParts);
            
            // Специальная обработка для help и update
            if ($action === 'help' || $action === 'update') {
                if ($action === 'help') {
                    $snmp = new DlinkSNMP();
                    $docs = $snmp->getApiDocs();
                    echo json_encode([
                        'success' => true,
                        'data' => $docs
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    exit;
                }
                // ... остальной код для update
            }
            
            // Для всех остальных действий требуется IP
            $ip = $_GET['ip'] ?? null;
            if (!$ip) {
                throw new Exception("Необходимо указать IP-адрес");
            }
            
            $snmp = new DlinkSNMP($ip);
            $result = null;
            
            switch ($action) {
                case 'info':
                    $result = $snmp->getSwitchInfo();
                    break;
                    
                case 'get':
                    if (!isset($_GET['ports'])) {
                        throw new Exception("Необходимо указать порты");
                    }
                    $result = $snmp->getPortVlan($_GET['ports']);
                    break;
                    
                case 'add':
                    if (!isset($_GET['ports']) || !isset($_GET['vlan'])) {
                        throw new Exception("Необходимо указать порты и VLAN");
                    }
                    $tagged = isset($_GET['tagged']) ? $_GET['tagged'] : false;
                    $result = $snmp->addPortsToVlan($_GET['ports'], $_GET['vlan'], $tagged);
                    break;
                    
                case 'remove':
                    if (!isset($_GET['ports']) || !isset($_GET['vlan'])) {
                        throw new Exception("Необходимо указать порты и VLAN");
                    }
                    $result = $snmp->removePortsFromVlan($_GET['ports'], $_GET['vlan']);
                    break;
                    
                case 'interfaces':
                    $result = $snmp->getInterfaces();
                    break;
                    
                case 'create':
                    if (!isset($_GET['vlan'])) {
                        throw new Exception("Необходимо указать ID VLAN");
                    }
                    $result = $snmp->createVlan($_GET['vlan']);
                    break;
                    
                case 'delete':
                    echo "DEBUG: Вход в case 'delete'\n";
                    echo "DEBUG: vlan = " . ($_GET['vlan'] ?? 'null') . "\n";
                    if ($_GET['vlan'] === null) {
                        throw new Exception("Необходимо указать ID VLAN");
                    }
                    $result = $snmp->deleteVlan($_GET['vlan']);
                    echo "VLAN " . $_GET['vlan'] . " успешно удален\n";
                    break;

                case 'vlans':
                    $result = $snmp->getVlanDetails();
                    break;

                case 'update':
                    try {
                        // Создаем временную директорию
                        $tempDir = sys_get_temp_dir() . '/dlink-snmp-api-update-' . uniqid();
                        mkdir($tempDir);
                        
                        // Клонируем репозиторий во временную директорию
                        exec("git clone https://github.com/kirush0280/dlink-snmp-api.git $tempDir 2>&1", $output, $returnVar);
                        
                        if ($returnVar !== 0) {
                            throw new Exception("Ошибка клонирования репозитория: " . implode("\n", $output));
                        }
                        
                        // Сохраняем текущий config.php
                        $currentConfig = file_get_contents('config.php');
                        
                        // Копируем файлы из временной директории
                        $files = [
                            'snmp_api.php',
                            'Logger.php',
                            'README.md'
                        ];
                        
                        foreach ($files as $file) {
                            if (file_exists($tempDir . '/' . $file)) {
                                copy($tempDir . '/' . $file, $file);
                            }
                        }
                        
                        // Восстанавливаем config.php
                        file_put_contents('config.php', $currentConfig);
                        
                        // Удаляем временную директорию
                        array_map('unlink', glob("$tempDir/*.*"));
                        rmdir($tempDir);
                        
                        echo json_encode([
                            'success' => true,
                            'message' => 'Скрипт успешно обновлен'
                        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                        exit;
                        
                    } catch (Exception $e) {
                        http_response_code(500);
                        echo json_encode([
                            'success' => false,
                            'error' => $e->getMessage()
                        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                        exit;
                    }
                    break;

                case 'help':
                    $snmp = new DlinkSNMP();
                    $docs = $snmp->getApiDocs();
                    echo json_encode([
                        'success' => true,
                        'data' => $docs
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    break;

                default:
                    throw new Exception("Неизвестное действие");
            }
            
            echo json_encode([
                'success' => true,
                'data' => $result
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            
        } catch (Exception $e) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        }
    }
}
?>
