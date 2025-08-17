#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from web3 import Web3
from hexbytes import HexBytes
from tabulate import tabulate

# ---------------------------
# SpenderSentry — аудит ERC-20 аппрувов
# ---------------------------

# Топик события Approval(address owner, address spender, uint256 value)
SIG_APPROVAL = Web3.keccak(text="Approval(address,address,uint256)").hex()

# Мини-ABI для ERC20
ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [{"name":"owner","type":"address"}], "name": "balanceOf",
     "outputs": [{"name":"","type":"uint256"}], "type":"function"},
    {"constant": True, "inputs": [{"name":"owner","type":"address"},{"name":"spender","type":"address"}],
     "name":"allowance","outputs":[{"name":"","type":"uint256"}], "type":"function"},
]

# Небольшой allowlist популярных/легитимных роутеров на mainnet (можете расширить)
SAFE_SPENDERS_ETH = {
    # Uniswap
    Web3.to_checksum_address("0xE592427A0AEce92De3Edee1F18E0157C05861564"): "Uniswap V3 SwapRouter",
    Web3.to_checksum_address("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"): "Uniswap V3 SwapRouter02",
    Web3.to_checksum_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"): "Uniswap V2 Router",
    # 1inch
    Web3.to_checksum_address("0x1111111254EEB25477B68fb85Ed929f73A960582"): "1inch Aggregation Router",
    # 0x
    Web3.to_checksum_address("0xDef1C0ded9bec7F1a1670819833240f027b25EfF"): "0x Exchange Proxy",
}

INFINITE_THRESHOLD = 2**255  # эвристика «бесконечного» аппрува

@dataclass
class AllowanceRow:
    token: str
    symbol: str
    decimals: int
    spender: str
    spender_tag: str
    allowance: str
    allowance_raw: int
    balance: str
    balance_raw: int
    risk: int  # 3 – высокий, 2 – средний, 1 – низкий

def human_amount(value: int, decimals: int) -> str:
    if decimals <= 0: 
        return str(value)
    scaled = value / (10 ** decimals)
    # до 8 знаков, без хвостовых нулей
    return f"{scaled:.8f}".rstrip('0').rstrip('.')

def get_token_meta(w3: Web3, addr: str) -> Tuple[str, int]:
    c = w3.eth.contract(address=addr, abi=ERC20_ABI)
    symbol, decimals = "UNKNOWN", 18
    try:
        symbol = c.functions.symbol().call()
    except Exception:
        pass
    try:
        decimals = int(c.functions.decimals().call())
    except Exception:
        pass
    return symbol, decimals

def get_allowance_balance(w3: Web3, token: str, owner: str, spender: str) -> Tuple[int, int]:
    c = w3.eth.contract(address=token, abi=ERC20_ABI)
    allow = 0
    bal = 0
    try:
        allow = int(c.functions.allowance(owner, spender).call())
    except Exception:
        pass
    try:
        bal = int(c.functions.balanceOf(owner).call())
    except Exception:
        pass
    return allow, bal

def chunk_ranges(start: int, end: int, step: int):
    cur = start
    while cur <= end:
        yield cur, min(end, cur + step - 1)
        cur += step

def calc_risk(allowance_raw: int, balance_raw: int, spender: str) -> int:
    # Простая, но полезная эвристика:
    # - 3: бесконечный аппрув ИЛИ allowance > 10 * balance, при этом spender НЕ в allowlist
    # - 2: allowance > balance (и не allowlist) ИЛИ бесконечный, но в allowlist
    # - 1: остальное
    is_infinite = allowance_raw >= INFINITE_THRESHOLD
    in_allow = spender in SAFE_SPENDERS_ETH
    if (is_infinite and not in_allow) or (balance_raw > 0 and allowance_raw > 10 * balance_raw and not in_allow):
        return 3
    if (allowance_raw > balance_raw and not in_allow) or (is_infinite and in_allow):
        return 2
    return 1

def scan_approvals(
    w3: Web3,
    owner: str,
    from_block: Optional[int],
    to_block: Optional[int],
    step: int = 3_000
) -> Dict[Tuple[str,str], int]:
    """
    Возвращает уникальные пары (token, spender) с последним зафиксированным raw value (не обязателен к использованию).
    """
    latest = w3.eth.block_number if to_block is None else to_block
    start = (latest - 200_000) if from_block is None else from_block
    start = max(start, 0)

    owner_topic = "0x" + "0"*24 + owner[2:].lower()  # indexed address topic (right-padded)
    pairs: Dict[Tuple[str,str], int] = {}

    for a, b in chunk_ranges(start, latest, step):
        filt = {
            "fromBlock": a,
            "toBlock": b,
            "topics": [SIG_APPROVAL, owner_topic],
        }
        logs = w3.eth.get_logs(filt)
        for lg in logs:
            token = Web3.to_checksum_address(lg["address"])
            spender_topic = lg["topics"][2].hex()
            spender = Web3.to_checksum_address("0x" + spender_topic[-40:])
            raw = int.from_bytes(HexBytes(lg["data"]), byteorder="big")
            pairs[(token, spender)] = raw  # храним последний встреченный
    return pairs

def build_report(w3: Web3, owner: str, pairs: Dict[Tuple[str,str], int]) -> List[AllowanceRow]:
    # кэш метаданных токенов
    meta: Dict[str, Tuple[str,int]] = {}
    rows: List[AllowanceRow] = []
    for (token, spender), _raw in pairs.items():
        if token not in meta:
            meta[token] = get_token_meta(w3, token)
        symbol, decimals = meta[token]
        allow_raw, bal_raw = get_allowance_balance(w3, token, owner, spender)
        allow_h = human_amount(allow_raw, decimals)
        bal_h = human_amount(bal_raw, decimals)
        tag = SAFE_SPENDERS_ETH.get(spender, "")
        risk = calc_risk(allow_raw, bal_raw, spender)
        rows.append(AllowanceRow(
            token=token, symbol=symbol, decimals=decimals,
            spender=spender, spender_tag=tag,
            allowance=allow_h, allowance_raw=allow_raw,
            balance=bal_h, balance_raw=bal_raw,
            risk=risk
        ))
    # сортировка: высокий риск, потом по allowance_raw по убыванию
    rows.sort(key=lambda r: (-r.risk, -r.allowance_raw))
    return rows

def print_table(rows: List[AllowanceRow], highlight_infinite: bool = True):
    table = []
    for r in rows:
        star = "★" if r.risk >= 3 else ("•" if r.risk == 2 else "")
        inf = " ∞" if (r.allowance_raw >= INFINITE_THRESHOLD and highlight_infinite) else ""
        tag = f" ({r.spender_tag})" if r.spender_tag else ""
        table.append([
            star,
            r.symbol,
            r.token,
            r.spender + tag,
            r.balance,
            r.allowance + inf,
            r.risk
        ])
    print(tabulate(table, headers=["!", "SYM", "TOKEN", "SPENDER", "BAL", "ALLOW", "RISK"], tablefmt="github"))

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="SpenderSentry",
        description="Аудит ERC-20 аппрувов: находит актуальные allowance'ы (token, spender) для указанного адреса."
    )
    ap.add_argument("--address", required=True, help="Ваш EVM-адрес (owner), например 0xabc...")
    ap.add_argument("--rpc", default="https://cloudflare-eth.com", help="RPC URL (по умолчанию Cloudflare Ethereum)")
    ap.add_argument("--from-block", type=int, help="Начальный блок для поиска Approval (по умолчанию ~последние 200k)")
    ap.add_argument("--to-block", type=int, help="Конечный блок (по умолчанию latest)")
    ap.add_argument("--step", type=int, default=3000, help="Размер чанка по блокам (по умолчанию 3000)")
    ap.add_argument("--json", dest="json_path", help="Путь для сохранения результата в JSON")
    ap.add_argument("--top", type=int, default=50, help="Ограничить количество строк вывода (после сортировки)")
    args = ap.parse_args(argv)

    owner = Web3.to_checksum_address(args.address)
    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        raise SystemExit("Не удалось подключиться к RPC. Проверьте --rpc.")

    print(f"Chain ID: {w3.eth.chain_id} | Latest block: {w3.eth.block_number}")
    print("Сканирую Approval события... (это оффчейн-лог без API-ключей)")

    pairs = scan_approvals(w3, owner, args.from_block, args.to_block, step=args.step)
    if not pairs:
        print("Не найдено ни одного Approval. Возможно, диапазон блоков мал или адрес не выдавал аппрувы.")
        return 0

    rows = build_report(w3, owner, pairs)

    # Табличный вывод (топ N)
    print("\nИтоги (отсортировано по риску и размеру allowance):")
    print_table(rows[:args.top])

    # JSON по запросу
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in rows], f, ensure_ascii=False, indent=2)
        print(f"\nJSON сохранён: {args.json_path}")

    # Подсказка по ревоку (безопасно, просто подсказка)
    print("\nПодсказка: для ревока можете вызвать у токена метод `approve(spender, 0)`.")
    print("Пример (web3.py): c.functions.approve('<SPENDER>', 0).transact({'from': owner})")
    print("Внимание: для отправки on-chain транзакций потребуется ваш ключ/кастодиал и gas.")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
