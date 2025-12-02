import dns.resolver
import logging
from django.conf import settings

logger = logging.getLogger('waf_engine')

class DomainVerifier:
    """
    Handles domain ownership verification via DNS TXT records.
    """
    
    VERIFICATION_PREFIX = "waf-verification="

    @staticmethod
    def verify_dns_record(domain, token):
        """
        Verify that a TXT record exists for the domain containing the verification token.
        
        Args:
            domain (str): The domain to verify (e.g., "example.com")
            token (str): The UUID token expected in the TXT record
            
        Returns:
            bool: True if verified, False otherwise
        """
        expected_value = f"{DomainVerifier.VERIFICATION_PREFIX}{token}"
        logger.info(f"Verifying domain {domain} with expected TXT record: {expected_value}")
        
        try:
            # Query TXT records for the domain
            answers = dns.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                # TXT records can be multi-string, join them
                txt_value = b''.join(rdata.strings).decode('utf-8')
                
                if expected_value in txt_value:
                    logger.info(f"Domain {domain} verified successfully.")
                    return True
                    
            logger.warning(f"Verification failed for {domain}. TXT record not found.")
            return False
            
        except dns.resolver.NXDOMAIN:
            logger.error(f"Domain {domain} does not exist.")
            return False
        except dns.resolver.NoAnswer:
            logger.warning(f"No TXT records found for {domain}.")
            return False
        except Exception as e:
            logger.error(f"DNS verification error for {domain}: {str(e)}")
            return False
