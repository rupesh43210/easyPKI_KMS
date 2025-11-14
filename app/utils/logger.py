"""
Utility functions - Logging setup
"""
import logging
import colorlog
from pathlib import Path
from logging.handlers import RotatingFileHandler

def setup_logging(config):
    """Setup application logging"""
    
    # Create logs directory
    log_path = Path(config['storage']['logs_path'])
    log_path.mkdir(parents=True, exist_ok=True)
    
    # Get log level
    log_level = getattr(logging, config['logging']['level'])
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Console handler with colors
    console_handler = colorlog.StreamHandler()
    console_handler.setLevel(log_level)
    console_format = colorlog.ColoredFormatter(
        '%(log_color)s%(levelname)-8s%(reset)s %(blue)s%(message)s',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # File handler
    file_handler = RotatingFileHandler(
        log_path / 'pki_kms.log',
        maxBytes=config['logging']['max_bytes'],
        backupCount=config['logging']['backup_count']
    )
    file_handler.setLevel(log_level)
    file_format = logging.Formatter(config['logging']['format'])
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)
    
    # Audit file handler
    if config['logging']['audit']['enabled']:
        audit_handler = RotatingFileHandler(
            log_path / 'audit.log',
            maxBytes=config['logging']['max_bytes'],
            backupCount=config['logging']['backup_count']
        )
        audit_handler.setLevel(logging.INFO)
        audit_format = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s'
        )
        audit_handler.setFormatter(audit_format)
        
        # Create audit logger
        audit_logger = logging.getLogger('audit')
        audit_logger.addHandler(audit_handler)
        audit_logger.setLevel(logging.INFO)
    
    return root_logger
