#!/usr/bin/env python3
"""
UEBA Technical Implementation Configuration
InfoSentinel Enterprise - User and Entity Behavior Analytics

This module configures and initializes the technical infrastructure
for the UEBA system including ML frameworks, big data processing,
real-time streaming, and search capabilities.
"""

import os
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

# ML Framework Imports
try:
    import sklearn
    import tensorflow as tf
    import torch
    import numpy as np
    import pandas as pd
    SKLEARN_AVAILABLE = True
    TENSORFLOW_AVAILABLE = True
    TORCH_AVAILABLE = True
except ImportError as e:
    logging.warning(f"ML Framework import error: {e}")
    SKLEARN_AVAILABLE = False
    TENSORFLOW_AVAILABLE = False
    TORCH_AVAILABLE = False

# Big Data Processing Imports
try:
    from pyspark.sql import SparkSession
    from pyspark.streaming import StreamingContext
    from pyspark.ml import Pipeline
    SPARK_AVAILABLE = True
except ImportError:
    logging.warning("Apache Spark not available")
    SPARK_AVAILABLE = False

# Real-time Stream Processing
try:
    import streamparse
    STORM_AVAILABLE = True
except ImportError:
    logging.warning("Apache Storm not available")
    STORM_AVAILABLE = False

# Search and Analytics
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    logging.warning("Elasticsearch not available")
    ELASTICSEARCH_AVAILABLE = False

@dataclass
class UEBAConfig:
    """UEBA System Configuration"""
    
    # ML Configuration
    sklearn_n_jobs: int = -1
    tensorflow_gpu_enabled: bool = True
    torch_device: str = "cuda" if torch.cuda.is_available() else "cpu"
    
    # Spark Configuration
    spark_app_name: str = "InfoSentinel-UEBA"
    spark_master: str = "local[*]"
    spark_executor_memory: str = "2g"
    spark_driver_memory: str = "1g"
    spark_streaming_batch_interval: int = 10  # seconds
    
    # Storm Configuration
    storm_nimbus_host: str = "localhost"
    storm_nimbus_port: int = 6627
    storm_topology_workers: int = 2
    storm_topology_parallelism: int = 4
    
    # Elasticsearch Configuration
    es_hosts: list = None
    es_index_prefix: str = "ueba"
    es_doc_type: str = "_doc"
    es_timeout: int = 30
    es_max_retries: int = 3
    
    # Data Processing
    batch_size: int = 1000
    max_memory_usage: str = "4GB"
    data_retention_days: int = 90
    
    # Model Configuration
    model_update_interval: int = 3600  # seconds
    baseline_update_interval: int = 86400  # seconds
    anomaly_threshold: float = 0.95
    risk_score_threshold: float = 0.8
    
    def __post_init__(self):
        if self.es_hosts is None:
            self.es_hosts = ["localhost:9200"]

class UEBATechnicalSetup:
    """Technical Infrastructure Setup for UEBA System"""
    
    def __init__(self, config: UEBAConfig = None):
        self.config = config or UEBAConfig()
        self.logger = logging.getLogger(__name__)
        self._spark_session = None
        self._es_client = None
        
    def initialize_all(self) -> Dict[str, bool]:
        """Initialize all technical components"""
        results = {
            "sklearn": self.setup_sklearn(),
            "tensorflow": self.setup_tensorflow(),
            "torch": self.setup_torch(),
            "spark": self.setup_spark(),
            "storm": self.setup_storm(),
            "elasticsearch": self.setup_elasticsearch()
        }
        
        self.logger.info(f"UEBA Technical Setup Results: {results}")
        return results
    
    def setup_sklearn(self) -> bool:
        """Configure Scikit-learn for UEBA ML models"""
        if not SKLEARN_AVAILABLE:
            return False
            
        try:
            # Configure sklearn for optimal performance
            os.environ['SKLEARN_ENABLE_RESOURCE_WARNINGS'] = 'false'
            os.environ['OMP_NUM_THREADS'] = str(self.config.sklearn_n_jobs)
            
            # Verify sklearn components needed for UEBA
            from sklearn.ensemble import IsolationForest
            from sklearn.svm import OneClassSVM
            from sklearn.cluster import KMeans
            from sklearn.preprocessing import StandardScaler
            from sklearn.decomposition import PCA
            
            self.logger.info("Scikit-learn configured successfully for UEBA")
            return True
            
        except Exception as e:
            self.logger.error(f"Scikit-learn setup failed: {e}")
            return False
    
    def setup_tensorflow(self) -> bool:
        """Configure TensorFlow for deep learning models"""
        if not TENSORFLOW_AVAILABLE:
            return False
            
        try:
            # Configure TensorFlow
            if self.config.tensorflow_gpu_enabled:
                gpus = tf.config.experimental.list_physical_devices('GPU')
                if gpus:
                    for gpu in gpus:
                        tf.config.experimental.set_memory_growth(gpu, True)
                    self.logger.info(f"TensorFlow GPU enabled: {len(gpus)} GPUs")
                else:
                    self.logger.warning("No GPUs found, using CPU")
            
            # Set random seed for reproducibility
            tf.random.set_seed(42)
            
            self.logger.info("TensorFlow configured successfully for UEBA")
            return True
            
        except Exception as e:
            self.logger.error(f"TensorFlow setup failed: {e}")
            return False
    
    def setup_torch(self) -> bool:
        """Configure PyTorch for neural networks"""
        if not TORCH_AVAILABLE:
            return False
            
        try:
            # Set device and random seed
            device = torch.device(self.config.torch_device)
            torch.manual_seed(42)
            
            if device.type == 'cuda':
                torch.cuda.manual_seed(42)
                self.logger.info(f"PyTorch GPU enabled: {torch.cuda.get_device_name()}")
            else:
                self.logger.info("PyTorch using CPU")
            
            self.logger.info("PyTorch configured successfully for UEBA")
            return True
            
        except Exception as e:
            self.logger.error(f"PyTorch setup failed: {e}")
            return False
    
    def setup_spark(self) -> bool:
        """Configure Apache Spark for big data processing"""
        if not SPARK_AVAILABLE:
            return False
            
        try:
            # Create Spark session
            self._spark_session = SparkSession.builder \
                .appName(self.config.spark_app_name) \
                .master(self.config.spark_master) \
                .config("spark.executor.memory", self.config.spark_executor_memory) \
                .config("spark.driver.memory", self.config.spark_driver_memory) \
                .config("spark.sql.adaptive.enabled", "true") \
                .config("spark.sql.adaptive.coalescePartitions.enabled", "true") \
                .getOrCreate()
            
            # Set log level
            self._spark_session.sparkContext.setLogLevel("WARN")
            
            self.logger.info("Apache Spark configured successfully for UEBA")
            return True
            
        except Exception as e:
            self.logger.error(f"Apache Spark setup failed: {e}")
            return False
    
    def setup_storm(self) -> bool:
        """Configure Apache Storm for real-time processing"""
        if not STORM_AVAILABLE:
            return False
            
        try:
            # Storm configuration would typically involve
            # topology definition and deployment
            storm_config = {
                "nimbus.host": self.config.storm_nimbus_host,
                "nimbus.thrift.port": self.config.storm_nimbus_port,
                "topology.workers": self.config.storm_topology_workers,
                "topology.max.task.parallelism": self.config.storm_topology_parallelism
            }
            
            self.logger.info("Apache Storm configuration prepared for UEBA")
            return True
            
        except Exception as e:
            self.logger.error(f"Apache Storm setup failed: {e}")
            return False
    
    def setup_elasticsearch(self) -> bool:
        """Configure Elasticsearch for search and analytics"""
        if not ELASTICSEARCH_AVAILABLE:
            return False
            
        try:
            # Create Elasticsearch client
            self._es_client = Elasticsearch(
                hosts=self.config.es_hosts,
                timeout=self.config.es_timeout,
                max_retries=self.config.es_max_retries,
                retry_on_timeout=True
            )
            
            # Test connection
            if self._es_client.ping():
                self.logger.info("Elasticsearch connection successful")
                
                # Create UEBA indices if they don't exist
                self._create_ueba_indices()
                return True
            else:
                self.logger.error("Elasticsearch connection failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Elasticsearch setup failed: {e}")
            return False
    
    def _create_ueba_indices(self):
        """Create Elasticsearch indices for UEBA data"""
        indices = [
            f"{self.config.es_index_prefix}-user-behavior",
            f"{self.config.es_index_prefix}-entity-behavior",
            f"{self.config.es_index_prefix}-risk-scores",
            f"{self.config.es_index_prefix}-anomalies",
            f"{self.config.es_index_prefix}-alerts"
        ]
        
        for index in indices:
            if not self._es_client.indices.exists(index=index):
                self._es_client.indices.create(
                    index=index,
                    body={
                        "settings": {
                            "number_of_shards": 1,
                            "number_of_replicas": 0
                        },
                        "mappings": {
                            "properties": {
                                "timestamp": {"type": "date"},
                                "user_id": {"type": "keyword"},
                                "entity_id": {"type": "keyword"},
                                "risk_score": {"type": "float"},
                                "anomaly_score": {"type": "float"},
                                "behavior_data": {"type": "object"}
                            }
                        }
                    }
                )
                self.logger.info(f"Created Elasticsearch index: {index}")
    
    def get_spark_session(self) -> Optional[SparkSession]:
        """Get the Spark session"""
        return self._spark_session
    
    def get_elasticsearch_client(self) -> Optional[Elasticsearch]:
        """Get the Elasticsearch client"""
        return self._es_client
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on all components"""
        health = {
            "sklearn": SKLEARN_AVAILABLE,
            "tensorflow": TENSORFLOW_AVAILABLE and tf.test.is_built_with_cuda() if TENSORFLOW_AVAILABLE else False,
            "torch": TORCH_AVAILABLE and torch.cuda.is_available() if TORCH_AVAILABLE else False,
            "spark": self._spark_session is not None,
            "storm": STORM_AVAILABLE,
            "elasticsearch": self._es_client.ping() if self._es_client else False
        }
        
        return health
    
    def cleanup(self):
        """Cleanup resources"""
        if self._spark_session:
            self._spark_session.stop()
            self.logger.info("Spark session stopped")
        
        if self._es_client:
            self._es_client.close()
            self.logger.info("Elasticsearch client closed")

# Global instance
ueba_tech_setup = UEBATechnicalSetup()

def initialize_ueba_infrastructure() -> Dict[str, bool]:
    """Initialize the complete UEBA technical infrastructure"""
    return ueba_tech_setup.initialize_all()

def get_ueba_config() -> UEBAConfig:
    """Get the UEBA configuration"""
    return ueba_tech_setup.config

def get_infrastructure_health() -> Dict[str, Any]:
    """Get infrastructure health status"""
    return ueba_tech_setup.health_check()

if __name__ == "__main__":
    # Initialize and test the infrastructure
    logging.basicConfig(level=logging.INFO)
    
    print("Initializing UEBA Technical Infrastructure...")
    results = initialize_ueba_infrastructure()
    
    print("\nSetup Results:")
    for component, status in results.items():
        status_str = "✓" if status else "✗"
        print(f"  {status_str} {component.upper()}")
    
    print("\nHealth Check:")
    health = get_infrastructure_health()
    for component, status in health.items():
        status_str = "✓" if status else "✗"
        print(f"  {status_str} {component.upper()}")