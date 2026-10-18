#!/usr/bin/env python
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "falconscan_backend.settings")

from apps.scans.apk_fuzzer import APKFuzzer

print('Starting reproduction: creating APKFuzzer with mutation_enabled=True')
f = APKFuzzer(package_name='com.example.test', components={'activities':[], 'services':[], 'receivers':[], 'providers':[]}, enabled=True, mutation_enabled=True, mutation_max_per_seed=2)
print('mutation_seed_file ->', getattr(f, 'mutation_seed_file', None))
