"""
Cache Manager for Web Security Scanner
Handles API response caching with TTL support and persistent storage
Reduces redundant API calls and improves scan performance
"""

import json
import time
import os
import sqlite3
from datetime import datetime, timedelta
from threading import Lock


class CacheManager:
    """
    Multi-tier caching system with in-memory and persistent SQLite storage.
    Features:
    - TTL (Time-to-Live) support for cache expiration
    - Thread-safe operations
    - Configurable cache key generation
    - Automatic cleanup of expired entries
    """
    
    def __init__(self, db_path=None):
        """
        Initialize cache manager.
        
        Args:
            db_path: Path to SQLite database file. Defaults to cache.db in project root
        """
        if db_path is None:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            db_path = os.path.join(project_root, 'cache.db')
        
        self.db_path = db_path
        self.memory_cache = {}  # In-memory cache for fast access
        self.lock = Lock()  # Thread safety
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for persistent caching."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cache (
                        cache_key TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        ttl_seconds INTEGER,
                        created_at REAL,
                        expires_at REAL,
                        hit_count INTEGER DEFAULT 0
                    )
                ''')
                
                # Create index for faster lookups
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_expires_at 
                    ON cache(expires_at)
                ''')
                
                conn.commit()
        except Exception as e:
            print(f"Cache database initialization error: {e}")
    
    def set(self, cache_key, data, ttl_seconds=86400):
        """
        Set cache entry with TTL.
        
        Args:
            cache_key: Unique cache identifier
            data: Data to cache (will be JSON serialized)
            ttl_seconds: Time-to-live in seconds (default: 24 hours)
        
        Returns:
            bool: True if cached successfully
        """
        with self.lock:
            try:
                created_at = time.time()
                expires_at = created_at + ttl_seconds
                
                # Store in memory
                self.memory_cache[cache_key] = {
                    'data': data,
                    'expires_at': expires_at,
                    'created_at': created_at,
                    'hit_count': 0
                }
                
                # Store in database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO cache 
                        (cache_key, data, ttl_seconds, created_at, expires_at, hit_count)
                        VALUES (?, ?, ?, ?, ?, 0)
                    ''', (cache_key, json.dumps(data), ttl_seconds, created_at, expires_at))
                    conn.commit()
                
                return True
            except Exception as e:
                print(f"Cache set error for key {cache_key}: {e}")
                return False
    
    def get(self, cache_key):
        """
        Retrieve cached data if not expired.
        
        Args:
            cache_key: Cache identifier to retrieve
        
        Returns:
            dict: Cached data if found and not expired, None otherwise
        """
        with self.lock:
            current_time = time.time()
            
            # Check memory cache first
            if cache_key in self.memory_cache:
                entry = self.memory_cache[cache_key]
                if entry['expires_at'] > current_time:
                    entry['hit_count'] = entry.get('hit_count', 0) + 1
                    return entry['data']
                else:
                    # Expired in memory, remove it
                    del self.memory_cache[cache_key]
            
            # Check database
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT data, expires_at, hit_count FROM cache 
                        WHERE cache_key = ?
                    ''', (cache_key,))
                    
                    row = cursor.fetchone()
                    if row:
                        data_str, expires_at, hit_count = row
                        
                        if expires_at > current_time:
                            data = json.loads(data_str)
                            
                            # Update hit count and reload to memory
                            cursor.execute('''
                                UPDATE cache SET hit_count = hit_count + 1 
                                WHERE cache_key = ?
                            ''', (cache_key,))
                            conn.commit()
                            
                            # Store in memory cache for fast access
                            self.memory_cache[cache_key] = {
                                'data': data,
                                'expires_at': expires_at,
                                'hit_count': hit_count + 1
                            }
                            
                            return data
                        else:
                            # Expired, delete from database
                            cursor.execute('DELETE FROM cache WHERE cache_key = ?', (cache_key,))
                            conn.commit()
            except Exception as e:
                print(f"Cache get error for key {cache_key}: {e}")
        
        return None
    
    def delete(self, cache_key):
        """Delete cache entry."""
        with self.lock:
            # Remove from memory
            if cache_key in self.memory_cache:
                del self.memory_cache[cache_key]
            
            # Remove from database
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM cache WHERE cache_key = ?', (cache_key,))
                    conn.commit()
            except Exception as e:
                print(f"Cache delete error: {e}")
    
    def clear(self):
        """Clear all cached data."""
        with self.lock:
            self.memory_cache.clear()
            
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM cache')
                    conn.commit()
            except Exception as e:
                print(f"Cache clear error: {e}")
    
    def cleanup_expired(self):
        """Remove expired entries from cache."""
        with self.lock:
            current_time = time.time()
            
            # Clean memory cache
            expired_keys = [k for k, v in self.memory_cache.items() 
                          if v['expires_at'] <= current_time]
            for key in expired_keys:
                del self.memory_cache[key]
            
            # Clean database
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM cache WHERE expires_at <= ?', (current_time,))
                    conn.commit()
            except Exception as e:
                print(f"Cleanup error: {e}")
    
    def get_stats(self):
        """Get cache statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM cache')
                total_entries = cursor.fetchone()[0]
                
                cursor.execute('SELECT SUM(hit_count) FROM cache')
                total_hits = cursor.fetchone()[0] or 0
                
                cursor.execute('''
                    SELECT COUNT(*) FROM cache WHERE expires_at > ?
                ''', (time.time(),))
                valid_entries = cursor.fetchone()[0]
                
                return {
                    'total_entries': total_entries,
                    'valid_entries': valid_entries,
                    'expired_entries': total_entries - valid_entries,
                    'total_hits': total_hits,
                    'memory_entries': len(self.memory_cache)
                }
        except Exception as e:
            print(f"Stats error: {e}")
            return {}


class APICallCacher:
    """
    Wrapper for API calls with automatic caching.
    Transparently caches HTTP responses and returns cached data on subsequent calls.
    """
    
    def __init__(self, cache_manager=None):
        """
        Initialize API call cacher.
        
        Args:
            cache_manager: CacheManager instance (creates new one if None)
        """
        self.cache = cache_manager or CacheManager()
    
    @staticmethod
    def _generate_cache_key(url, params=None, method='GET'):
        """
        Generate cache key from URL and parameters.
        
        Args:
            url: Request URL
            params: Query parameters (dict)
            method: HTTP method
        
        Returns:
            str: Cache key identifier
        """
        import hashlib
        
        key_string = f"{method}:{url}"
        if params:
            # Sort params for consistent key generation
            sorted_params = sorted(params.items())
            key_string += ':' + json.dumps(sorted_params)
        
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get_cached_response(self, url, params=None, ttl_seconds=86400, headers=None, timeout=10):
        """
        Perform GET request with caching.
        
        Args:
            url: Request URL
            params: Query parameters (dict)
            ttl_seconds: Cache TTL in seconds (default: 24 hours)
            headers: Request headers (dict)
            timeout: Request timeout in seconds
        
        Returns:
            dict: Response data or None on failure
        """
        import requests
        
        cache_key = self._generate_cache_key(url, params)
        
        # Try to get from cache
        cached_data = self.cache.get(cache_key)
        if cached_data is not None:
            cached_data['_from_cache'] = True
            return cached_data
        
        # Not in cache, make request
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers or {},
                timeout=timeout,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json() if response.headers.get('content-type', '').count('application/json') > 0 else response.text
                result = {
                    'status_code': response.status_code,
                    'data': data,
                    'headers': dict(response.headers),
                    '_from_cache': False,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Cache the response
                self.cache.set(cache_key, result, ttl_seconds)
                return result
            else:
                print(f"API request failed with status {response.status_code}")
                return None
        except Exception as e:
            print(f"API request error: {e}")
            return None
    
    def post_cached_response(self, url, data=None, ttl_seconds=3600, headers=None, timeout=10):
        """
        Perform POST request with caching (useful for APIs that accept POST).
        
        Args:
            url: Request URL
            data: Request body (dict)
            ttl_seconds: Cache TTL in seconds (default: 1 hour)
            headers: Request headers (dict)
            timeout: Request timeout in seconds
        
        Returns:
            dict: Response data or None on failure
        """
        import requests
        
        # For POST, include data in cache key
        cache_key = self._generate_cache_key(url, data, 'POST')
        
        # Try cache first
        cached_data = self.cache.get(cache_key)
        if cached_data is not None:
            cached_data['_from_cache'] = True
            return cached_data
        
        # Not in cache, make request
        try:
            response = requests.post(
                url,
                json=data,
                headers=headers or {},
                timeout=timeout,
                verify=False
            )
            
            if response.status_code == 200:
                result = {
                    'status_code': response.status_code,
                    'data': response.json(),
                    'headers': dict(response.headers),
                    '_from_cache': False,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Cache the response
                self.cache.set(cache_key, result, ttl_seconds)
                return result
            else:
                return None
        except Exception as e:
            print(f"POST request error: {e}")
            return None


# Global cache instance
_global_cache = None


def get_cache_manager():
    """Get or create global cache manager instance."""
    global _global_cache
    if _global_cache is None:
        _global_cache = CacheManager()
    return _global_cache


def get_api_cacher():
    """Get or create global API call cacher instance."""
    cache_mgr = get_cache_manager()
    return APICallCacher(cache_mgr)
