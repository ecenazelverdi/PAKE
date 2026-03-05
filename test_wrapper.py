import ristretto as R

x = R.random_scalar()
X = R.base_mult(x)

print("Public key:", X.hex())
print("Hash of element:", R.hash_point(X).hex())