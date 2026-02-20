"""
Cache Manager for API responses and scan results
Implements SQLite + in-memory caching with 24-hour TTL
"""

import sqlite3
import json
import pickle
import os
from datetime import datetime, timedelta
from threading import Lock
import requests


class CacheManager:
    """
    Hybrid cache manager using SQLite (persistent) + in-memory (fast)
    Automatically expires entries after 24 hours
    """
    
    def __init__(self, db_path='cache.db'):
        """
        Initialize cache manager
        
        Args:
            db_path (str): Path to SQLite database file
        """
        self.db_path = db_path
        self.memory_cache = {}  # In-memory cache
        self.lock = Lock()  # Thread-safe operations
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with cache table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create cache table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL,
                    expires_at DATETIME NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for faster lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)
            ''')
            
            conn.commit()
            conn.close()
            
            print("✅ Cache database initialized")
            
        except Exception as e:
            print(f"❌ Error initializing cache: {str(e)}")
    
    def get(self, key):
        """
        Retrieve value from cache (checks memory first, then SQLite)
        
        Args:
            key (str): Cache key
        
        Returns:
            Any: Cached value or None if not found/expired
        """
        try:
            with self.lock:
                # ✅ CHECK IN-MEMORY CACHE FIRST (fastest)
                if key in self.memory_cache:
                    cached_item = self.memory_cache[key]
                    
                    # Check expiry
                    if datetime.utcnow() < cached_item['expires_at']:
                        print(f"💾 Cache HIT (memory): {key}")
                        return cached_item['value']
                    else:
                        # Expired, remove it
                        del self.memory_cache[key]
                        print(f"⏰ Cache EXPIRED (memory): {key}")
                
                # ✅ CHECK SQLITE CACHE (persistent)
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute(
                    'SELECT value, expires_at FROM cache WHERE key = ?',
                    (key,)
                )
                
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    value_bytes, expires_at_str = row
                    expires_at = datetime.fromisoformat(expires_at_str)
                    
                    # Check expiry
                    if datetime.utcnow() < expires_at:
                        # Deserialize and restore to memory
                        value = pickle.loads(value_bytes)
                        self.memory_cache[key] = {
                            'value': value,
                            'expires_at': expires_at
                        }
                        print(f"💾 Cache HIT (disk): {key}")
                        return value
                    else:
                        # Expired, delete it
                        self._delete_expired(key)
                        print(f"⏰ Cache EXPIRED (disk): {key}")
                
                print(f"❌ Cache MISS: {key}")
                return None
        
        except Exception as e:
            print(f"❌ Cache GET error: {str(e)}")
            return None
    
    def set(self, key, value, ttl=86400):
        """
        Store value in cache (both memory and SQLite)
        
        Args:
            key (str): Cache key
            value (Any): Value to cache
            ttl (int): Time to live in seconds (default 24 hours)
        """
        try:
            with self.lock:
                expires_at = datetime.utcnow() + timedelta(seconds=ttl)
                
                # ✅ STORE IN MEMORY
                self.memory_cache[key] = {
                    'value': value,
                    'expires_at': expires_at
                }
                
                # ✅ STORE IN SQLITE (persistent)
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                value_bytes = pickle.dumps(value)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO cache (key, value, expires_at)
                    VALUES (?, ?, ?)
                ''', (key, value_bytes, expires_at.isoformat()))
                
                conn.commit()
                conn.close()
                
                print(f"✅ Cache SET: {key} (TTL: {ttl}s)")
        
        except Exception as e:
            print(f"❌ Cache SET error: {str(e)}")
    
    def delete(self, key):
        """
        Delete value from cache
        
        Args:
            key (str): Cache key
        """
        try:
            with self.lock:
                # Remove from memory
                if key in self.memory_cache:
                    del self.memory_cache[key]
                
                # Remove from SQLite
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM cache WHERE key = ?', (key,))
                conn.commit()
                conn.close()
                
                print(f"🗑️ Cache DELETED: {key}")
        
        except Exception as e:
            print(f"❌ Cache DELETE error: {str(e)}")
    
    def clear(self):
        """Clear entire cache"""
        try:
            with self.lock:
                # Clear memory
                self.memory_cache.clear()
                
                # Clear SQLite
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM cache')
                conn.commit()
                conn.close()
                
                print("🗑️ Cache CLEARED")
        
        except Exception as e:
            print(f"❌ Cache CLEAR error: {str(e)}")
    
    def cleanup_expired(self):
        """Remove all expired entries from cache"""
        try:
            with self.lock:
                # Clean memory cache
                expired_keys = []
                for key, item in self.memory_cache.items():
                    if datetime.utcnow() >= item['expires_at']:
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self.memory_cache[key]
                
                if expired_keys:
                    print(f"🧹 Cleaned {len(expired_keys)} expired entries from memory")
                
                # Clean SQLite cache
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute(
                    'DELETE FROM cache WHERE expires_at < ?',
                    (datetime.utcnow().isoformat(),)
                )
                
                deleted = cursor.rowcount
                conn.commit()
                conn.close()
                
                if deleted > 0:
                    print(f"🧹 Cleaned {deleted} expired entries from disk")
        
        except Exception as e:
            print(f"❌ Cache CLEANUP error: {str(e)}")
    
    def _delete_expired(self, key):
        """Delete single expired key from SQLite"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM cache WHERE key = ?', (key,))
            conn.commit()
            conn.close()
        except:
            pass
    
    def get_cached_response(self, url, headers=None, params=None, ttl=86400):
        """
        Get HTTP response with caching
        
        Args:
            url (str): URL to fetch
            headers (dict): HTTP headers
            params (dict): Query parameters
            ttl (int): Cache time-to-live in seconds
        
        Returns:
            requests.Response: HTTP response object
        """
        # Create cache key from URL + params
        cache_key = f"http_{url}_{json.dumps(params or {})}"
        
        # Check cache first
        cached = self.get(cache_key)
        if cached:
            return cached
        
        # Fetch from API
        try:
            response = requests.get(
                url,
                headers=headers or {},
                params=params or {},
                timeout=10
            )
            
            # Cache the response
            self.set(cache_key, response, ttl=ttl)
            
            return response
        
        except Exception as e:
            print(f"❌ HTTP request error: {str(e)}")
            return None
    
    def stats(self):
        """Get cache statistics"""
        try:
            with self.lock:
                memory_items = len(self.memory_cache)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM cache')
                disk_items = cursor.fetchone()[0]
                
                cursor.execute('SELECT SUM(LENGTH(value)) FROM cache')
                disk_size = cursor.fetchone()[0] or 0
                
                conn.close()
                
                return {
                    'memory_items': memory_items,
                    'disk_items': disk_items,
                    'disk_size_bytes': disk_size,
                    'disk_size_mb': round(disk_size / 1024 / 1024, 2),
                    'total_items': memory_items + disk_items
                }
        
        except Exception as e:
            print(f"❌ Stats error: {str(e)}")
            return None


# ==================== GLOBAL SINGLETON ====================

_cache_manager = None


def get_api_cacher():
    """
    Get global cache manager instance (singleton pattern)
    
    Returns:
        CacheManager: Global cache manager instance
    """
    global _cache_manager
    
    if _cache_manager is None:
        # Calculate path to 'database/cache.db' from 'core/utils/cache_manager.py'
        # Go up 3 levels: utils -> core -> root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        db_path = os.path.join(base_dir, 'database', 'cache.db')
        
        _cache_manager = CacheManager(db_path)
    
    return _cache_manager


def clear_cache():
    """Clear all cached data"""
    cacher = get_api_cacher()
    cacher.clear()


def cache_stats():
    """Get cache statistics"""
    cacher = get_api_cacher()
    return cacher.stats()


def cleanup_expired_cache():
    """Remove expired cache entries"""
    cacher = get_api_cacher()
    cacher.cleanup_expired()
