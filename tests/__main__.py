import os
import sys
import subprocess

# Add the parent directory to sys.path so 'pake' can be found
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

def run_tests():
    tests_dir = os.path.dirname(__file__)
    test_files = [f for f in os.listdir(tests_dir) if f.startswith('test_') and f.endswith('.py')]
    test_files.sort()

    print(f"Discovered {len(test_files)} test files in {tests_dir}\n")

    failed_tests = []

    for test_file in test_files:
        test_path = os.path.join(tests_dir, test_file)
        print(f"--- Running {test_file} ---")
        
        # Run as a subprocess to ensure clean environment and PYTHONPATH
        env = os.environ.copy()
        env['PYTHONPATH'] = BASE_DIR + (os.pathsep + env.get('PYTHONPATH', '') if env.get('PYTHONPATH') else '')
        
        try:
            # We use 'python3' and the full path
            result = subprocess.run([sys.executable, test_path], env=env, capture_output=False)
            if result.returncode != 0:
                print(f"FAILED: {test_file} returned exit code {result.returncode}")
                failed_tests.append(test_file)
            else:
                print(f"SUCCESS: {test_file}")
        except Exception as e:
            print(f"ERROR running {test_file}: {e}")
            failed_tests.append(test_file)
        print("-" * 40)

    if failed_tests:
        print(f"\nSummary: {len(failed_tests)} tests failed: {', '.join(failed_tests)}")
        sys.exit(1)
    else:
        print("\nSummary: All tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    run_tests()
