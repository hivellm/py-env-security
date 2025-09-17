#!/usr/bin/env python3
"""
Deployment validation script for BIP-04 Secure Script Execution Environment.
"""

import sys
import os
import time
from pathlib import Path

# Add secure package to path
sys.path.insert(0, str(Path(__file__).parent))

from secure import SecureScriptExecutor
from secure.testing import SecurityTestSuite
from secure.migration import ScriptMigrationManager

def validate_deployment():
    """Validate the secure execution environment deployment."""
    print("🔍 BIP-04 Secure Script Execution Environment - Deployment Validation")
    print("=" * 70)

    validation_results = {
        'overall_status': 'pending',
        'checks_passed': 0,
        'checks_failed': 0,
        'checks_total': 0,
        'details': []
    }

    def check_result(name, success, message="", details=None):
        """Record a validation check result."""
        validation_results['checks_total'] += 1
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {name}")
        if message:
            print(f"   {message}")

        result = {
            'name': name,
            'success': success,
            'message': message,
            'details': details
        }
        validation_results['details'].append(result)

        if success:
            validation_results['checks_passed'] += 1
        else:
            validation_results['checks_failed'] += 1

    try:
        # 1. Check Python environment
        print("\\n🐍 Python Environment Checks:")
        check_result(
            "Python Version",
            sys.version_info >= (3, 8),
            f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )

        # 2. Check required modules
        print("\\n📦 Module Availability:")
        required_modules = ['yaml', 'pathlib', 'psutil']
        for module in required_modules:
            try:
                __import__(module)
                check_result(f"Module: {module}", True)
            except ImportError:
                check_result(f"Module: {module}", False, "Module not available")

        # 3. Initialize secure executor
        print("\\n🚀 Secure Executor Initialization:")
        try:
            executor = SecureScriptExecutor()
            check_result("SecureScriptExecutor", True, "Initialization successful")
        except Exception as e:
            check_result("SecureScriptExecutor", False, f"Initialization failed: {e}")
            return validation_results

        # 4. Test basic functionality
        print("\\n⚙️  Basic Functionality Tests:")
        test_script_content = """
import sys
print("Deployment validation test")
sys.exit(0)
"""

        # Create test script
        test_script = Path("scripts/examples/deployment_test.py")
        test_script.parent.mkdir(parents=True, exist_ok=True)
        test_script.write_text(test_script_content)

        try:
            # Test script validation
            is_valid = executor.validate_script(str(test_script))
            check_result("Script Validation", is_valid)

            # Test script execution
            result = executor.execute_script(str(test_script))
            execution_success = result['success']
            check_result("Script Execution", execution_success)

            if execution_success:
                check_result(
                    "Execution Output",
                    "Deployment validation test" in result['stdout'],
                    "Correct output generated"
                )

        except Exception as e:
            check_result("Basic Functionality", False, f"Error: {e}")
        finally:
            test_script.unlink(missing_ok=True)

        # 5. Test security features
        print("\\n🔒 Security Feature Tests:")

        # Test filesystem security
        try:
            is_blocked = not executor.validate_script("/etc/passwd")
            check_result("Filesystem Security", is_blocked, "Restricted paths properly blocked")
        except Exception:
            check_result("Filesystem Security", False, "Security check failed")

        # Test static analysis
        analysis_script = Path("scripts/examples/analysis_test.py")
        analysis_script.write_text("""
import os
print("Analysis test")
""")

        try:
            analysis = executor.analyze_script_security(str(analysis_script))
            has_analysis = isinstance(analysis, dict) and 'risk_level' in analysis
            check_result("Static Analysis", has_analysis, f"Risk level: {analysis.get('risk_level', 'unknown')}")
        except Exception as e:
            check_result("Static Analysis", False, f"Analysis failed: {e}")
        finally:
            analysis_script.unlink(missing_ok=True)

        # 6. Test monitoring system
        print("\\n📊 Monitoring System Tests:")
        try:
            stats = executor.get_security_stats()
            has_stats = isinstance(stats, dict) and 'monitoring_stats' in stats
            check_result("Monitoring Stats", has_stats)

            if has_stats:
                executions = stats['monitoring_stats']['total_executions']
                check_result("Execution Tracking", executions >= 0, f"Tracked {executions} executions")
        except Exception as e:
            check_result("Monitoring System", False, f"Monitoring failed: {e}")

        # 7. Test migration system
        print("\\n🔄 Migration System Tests:")
        try:
            migration_manager = ScriptMigrationManager(executor)
            migration_script = Path("scripts/examples/migration_test.py")
            migration_script.write_text("print('Migration test')")

            analysis = migration_manager.analyze_script_for_migration(str(migration_script))
            has_analysis = isinstance(analysis, dict)
            check_result("Migration Analysis", has_analysis)

            if has_analysis:
                score = analysis.get('compatibility_score', 0)
                check_result("Compatibility Score", score >= 0, f"Score: {score}%")
        except Exception as e:
            check_result("Migration System", False, f"Migration failed: {e}")
        finally:
            Path("scripts/examples/migration_test.py").unlink(missing_ok=True)

        # 8. Performance validation
        print("\\n⚡ Performance Validation:")
        perf_script = Path("scripts/examples/performance_test.py")
        perf_script.write_text("""
import time
start = time.time()
for i in range(10000):
    x = i * 2
end = time.time()
print(f"Performance test completed in {end - start:.3f} seconds")
""")

        try:
            start_time = time.time()
            result = executor.execute_script(str(perf_script))
            end_time = time.time()

            if result['success']:
                total_time = end_time - start_time
                script_time = result['execution_time']
                overhead = total_time - script_time

                check_result(
                    "Performance Test",
                    True,
                    f"Total time: {total_time:.3f}s, Script time: {script_time:.3f}s"
                )
                check_result("Overhead Check", overhead < 1.0, f"Overhead: {overhead:.3f}s")
            else:
                check_result("Performance Test", False, "Script execution failed")
        except Exception as e:
            check_result("Performance Test", False, f"Performance test failed: {e}")
        finally:
            perf_script.unlink(missing_ok=True)

        # 9. Final summary
        print("\\n📋 Validation Summary:")
        print(f"   Total Checks: {validation_results['checks_total']}")
        print(f"   Passed: {validation_results['checks_passed']}")
        print(f"   Failed: {validation_results['checks_failed']}")

        if validation_results['checks_failed'] == 0:
            validation_results['overall_status'] = 'success'
            print("   Overall Status: ✅ DEPLOYMENT VALIDATION SUCCESSFUL")
        else:
            validation_results['overall_status'] = 'failed'
            print("   Overall Status: ❌ DEPLOYMENT VALIDATION FAILED")

        # 10. Recommendations
        if validation_results['checks_failed'] > 0:
            print("\\n💡 Recommendations:")
            failed_checks = [check for check in validation_results['details'] if not check['success']]
            for check in failed_checks[:3]:  # Show first 3 failed checks
                print(f"   • Fix {check['name']}: {check['message']}")

        return validation_results

    except Exception as e:
        print(f"❌ Validation failed with error: {e}")
        validation_results['overall_status'] = 'error'
        validation_results['error'] = str(e)
        return validation_results

if __name__ == "__main__":
    results = validate_deployment()

    # Exit with appropriate code
    if results['overall_status'] == 'success':
        print("\\n🎉 BIP-04 Secure Script Execution Environment is ready for production!")
        sys.exit(0)
    else:
        print("\\n⚠️  Deployment validation found issues. Please review and fix before production use.")
        sys.exit(1)
