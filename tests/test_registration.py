from pake import registration as r

def test_registration():
    print("Running registration tests...")
    
    # Test 1: Basic registration
    rec = r.register('hunter2', b'alice', b'server')
    print("Test 1: Basic output format")
    print('w0  :', rec['w0'].hex())
    print('w1  :', rec['w1'].hex())
    print('L   :', rec['L'].hex())
    print('M   :', rec['M'].hex())
    print('N   :', rec['N'].hex())
    print('salt:', rec['salt'].hex())
    print()

    # Test 2: Same password + salt -> same w0, w1 deterministically
    rec2 = r.register('hunter2', b'alice', b'server', salt=rec['salt'])
    assert rec['w0'] == rec2['w0'], 'w0 not deterministic!'
    assert rec['w1'] == rec2['w1'], 'w1 not deterministic!'
    print('Test 2: Determinism check PASS')

    # Test 3: Different password -> different w0, w1
    rec3 = r.register('wrongpass', b'alice', b'server', salt=rec['salt'])
    assert rec['w0'] != rec3['w0'], 'w0 should differ with wrong password!'
    print('Test 3: Different password check PASS')

    # Test 4: M and N are stable constants across calls
    rec4 = r.register('abc', b'x', b'y')
    assert rec4['M'] == rec['M'], 'M should be constant!'
    assert rec4['N'] == rec['N'], 'N should be constant!'
    print('Test 4: M/N stability check PASS')
    
    print("\nAll tests passed successfully!")

if __name__ == "__main__":
    test_registration()
