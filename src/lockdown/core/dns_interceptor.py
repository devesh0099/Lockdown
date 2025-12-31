import socket
import threading
import logging
import re
from typing import Optional, Callable
from core.dns_resolver import DNSResolver

logger = logging.getLogger(__name__)


class DNSInterceptor:
    def __init__(self, whitelist_patterns: list, on_ip_resolved: Optional[Callable] = None):
        self.whitelist_patterns = [re.compile(pattern) for pattern in whitelist_patterns]
        self.on_ip_resolved = on_ip_resolved
        self.resolver = DNSResolver()
        self.BIND_IP = "127.0.0.1"
        self.BIND_PORT = 53

        self.sock = None
        self.running = False
        self.thread = None

    def start(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.BIND_IP, self.BIND_PORT))
            self.running = True
            self.thread = threading.Thread(target=self._listen, daemon=True)
            self.thread.start()
            
            logger.info(f"✓ DNS Interceptor listening on {self.BIND_IP}:{self.BIND_PORT}")
            return True
            
        except PermissionError:
            logger.error("Permission denied Run as Administrator")
            return False
        except OSError as e:
            logger.error(f"Failed to bind port 53: {e}")
            logger.error("Another DNS service may be using port 53")
            return False
        except Exception as e:
            logger.error(f"Failed to start DNS interceptor: {e}")
            return False
        
    def stop(self):
        logger.info("Stopping DNS interceptor")
        self.running = False
        
        if self.sock:
            self.sock.close()
        
        if self.thread:
            self.thread.join(timeout=2)
        
        logger.info("DNS interceptor stopped")

    def _listen(self):
        logger.info("DNS interceptor thread started")
        
        while self.running:
            try:
                data, client_addr = self.sock.recvfrom(512)
            
                threading.Thread(
                    target=self._handle_query,
                    args=(data, client_addr),
                    daemon=True
                ).start()
            except OSError as e:
                if e.winerror == 10054:
                    continue
                if self.running:
                    logger.error(f"Error in DNS listener: {e}")
            except Exception as e:
                if self.running:
                    logger.error(f"Error in DNS listener: {e}")
    
    def _handle_query(self, query_data: bytes, client_addr):
        try:
            domain = self._extract_domain(query_data)
            
            if not domain:
                logger.warning(f"Could not extract domain from query")
                return
            
            logger.debug(f"DNS query: {domain} from {client_addr}")
            
            if self._is_whitelisted(domain):
                logger.info(f"Allowed domain: {domain}")
                ips = self.resolver.resolve(domain, query_type="A")
                
                if ips:
                    for ip in ips:
                        if self.on_ip_resolved:
                            self.on_ip_resolved(domain, ip)
                    
                    response = self._build_response(query_data, ips)
                    self.sock.sendto(response, client_addr)
                else:
                    response = self._build_error_response(query_data, rcode=2)
                    self.sock.sendto(response, client_addr)
            else:
                logger.info(f"Blocked domain: {domain}")
                
                response = self._build_error_response(query_data, rcode=3)
                self.sock.sendto(response, client_addr)
                
        except Exception as e:
            logger.error(f"Error handling DNS query: {e}")
    
    def _is_whitelisted(self, domain: str) -> bool:
        for pattern in self.whitelist_patterns:
            if pattern.match(domain):
                return True
        return False
    
    def _extract_domain(self, query_data: bytes) -> Optional[str]:
        try:
            offset = 12
            domain_parts = []
            
            while True:
                length = query_data[offset]
                if length == 0:
                    break
                
                offset += 1
                domain_parts.append(query_data[offset:offset+length].decode('ascii'))
                offset += length
            
            return '.'.join(domain_parts) if domain_parts else None
            
        except Exception as e:
            logger.error(f"Error extracting domain: {e}")
            return None
    
    def _build_response(self, query_data: bytes, ips: list) -> bytes:
        response = bytearray(query_data[:2])
        
        response += b'\x81\x80'
        
        response += b'\x00\x01'
        response += len(ips).to_bytes(2, 'big')
        response += b'\x00\x00\x00\x00'
        
        offset = 12
        while query_data[offset] != 0:
            offset += 1
        offset += 5
        response += query_data[12:offset]

        for ip in ips:
            response += b'\xc0\x0c'
            response += b'\x00\x01\x00\x01'
            response += b'\x00\x00\x01\x2c'
            response += b'\x00\x04'
            response += bytes(int(octet) for octet in ip.split('.'))
        
        return bytes(response)
    
    def _build_error_response(self, query_data: bytes, rcode: int) -> bytes:
        response = bytearray(query_data[:2])
        flags = 0x8180 | rcode
        response += flags.to_bytes(2, 'big')
        response += query_data[4:12]
        offset = 12
        while query_data[offset] != 0:
            offset += 1
        offset += 5
        response += query_data[12:offset]
        return bytes(response)


