import math

def calculate_compound_interest(principal: float, rate: float, years: int) -> float:
    """Calculates annual compound interest."""
    amount = principal * (math.pow((1 + (rate / 100)), years))
    return round(amount, 2)

if __name__ == "__main__":
    p = 10000.0
    r = 5.5
    t = 10
    print(f"Initial: ${p}, Rate: {r}%, Years: {t}")
    print(f"Final Value: ${calculate_compound_interest(p, r, t)}")
