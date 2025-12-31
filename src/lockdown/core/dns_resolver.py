import socket
import struct
import logging

logger = logging.getLogger(__name__)

UPSTREAM_SERVERS = [
        "8.8.8.8", 
        "1.1.1.1", 
        "208.67.222.222" 
    ]

DNS_PORT = 53
TIMEOUT = 5

class DNSResolver:
    
    def __init__(self):
        self.upstream_servers = UPSTREAM_SERVERS
        
    def resolve(self, domain: str, query_type: str = "A") -> list[str]:
        for upstream in self.upstream_servers:
            try:
                logger.debug(f"Querying {upstream} for {domain} ({query_type})")
                
                query_packet = self._build_query(domain, query_type)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(TIMEOUT)
                sock.sendto(query_packet, (upstream, DNS_PORT))
                
                response, _ = sock.recvfrom(512)
                sock.close()
                
                ips = self._parse_response(response, query_type)
                
                if ips:
                    logger.info(f"Resolved {domain} → {ips}")
                    return ips
                else:
                    logger.warning(f"No {query_type} records found for {domain}")
                    
            except socket.timeout:
                logger.warning(f"Timeout querying {upstream} for {domain}")
                continue
            except Exception as e:
                logger.warning(f"Error querying {upstream}: {e}")
                continue
        
        logger.error(f"Failed to resolve {domain} (all upstreams failed)")
        return []
    
    def _build_query(self, domain: str, query_type: str) -> bytes:
        import random
        transaction_id = random.randint(0, 65535)
        flags = 0x0100
        
        header = struct.pack('>HHHHHH', transaction_id, flags, 1, 0, 0, 0)
        
        question = self._encode_domain(domain)
        
        qtype = 1 if query_type == "A" else 28
        qclass = 1 
        
        question += struct.pack('>HH', qtype, qclass)
        
        return header + question
    
    def _encode_domain(self, domain: str) -> bytes:
        encoded = b''
        for label in domain.split('.'):
            encoded += bytes([len(label)]) + label.encode('ascii')
        encoded += b'\x00'  
        return encoded
    
    def _parse_response(self, response: bytes, query_type: str) -> list[str]:
        try:
            rcode = response[3] & 0x0F
            if rcode != 0:
                logger.debug(f"DNS error code: {rcode}")
                return []
                        
            answer_count = struct.unpack('>H', response[6:8])[0]
            
            if answer_count == 0:
                return []
            
            offset = 12
            
            while response[offset] != 0:
                offset += 1
            offset += 5  
            
            ips = []
            for _ in range(answer_count):
                
                if response[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while response[offset] != 0:
                        offset += 1
                    offset += 1
                
                rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
                offset += 10
                
                if rtype == 1 and query_type == "A":  
                    if rdlength == 4:
                        ip = '.'.join(str(b) for b in response[offset:offset+4])
                        ips.append(ip)
                
                elif rtype == 28 and query_type == "AAAA":  
                    if rdlength == 16:
                        
                        ip_parts = struct.unpack('>8H', response[offset:offset+16])
                        ip = ':'.join(f'{part:x}' for part in ip_parts)
                        ips.append(ip)
                
                offset += rdlength
            
            return ips
            
        except Exception as e:
            logger.error(f"Error parsing DNS response: {e}")
            return []