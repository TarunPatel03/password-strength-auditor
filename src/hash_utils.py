from argon2 import PasswordHasher

# Sensible interactive defaults; tune for servers (higher memory/time)
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)


def argon2_hash(password: str) -> str:
    return PH.hash(password)


def argon2_verify(hash_str: str, password: str) -> bool:
    try:
        return PH.verify(hash_str, password)
    except Exception:
        return False
