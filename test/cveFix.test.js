'use strict';

const expect = require('expect.js');
const { performance } = require('perf_hooks');
const escapeArgument = require('../lib/util/escapeArgument');

describe('escapeArgument CVE-2024-21538 mitigation', function () {
    this.timeout(35000); // allow up to 35s to cover edge stress

    it('should escape benign input correctly', () => {
        const input = 'normal input with spaces and quotes "like this"';
        const result = escapeArgument(input, true);

        // Check it's a string and doesn't throw
        expect(result).to.be.a('string');
        expect(result).to.contain('"');
    });

    it('should not hang or crash on malicious input (long backslashes + quote)', () => {
        const malicious = ('\\\\\\\\\\\\\\'.repeat(1e6)) + '"'; // 9 million backslashes + quote
        const start = performance.now();

        const result = escapeArgument(malicious, true);
        const end = performance.now();

        const elapsed = end - start;

        console.log(`escapeArgument execution time: ${elapsed.toFixed(2)}ms`);

        expect(result).to.be.a('string');
        expect(elapsed).to.be.lessThan(30000); // Must finish in under 30s
    });

    it('should escape input containing only backslashes and quotes without hanging', () => {
        const input = '\\\\\\\\"\\\\"'.repeat(500000); // 5M chars
        const start = performance.now();

        const result = escapeArgument(input, true);
        const end = performance.now();

        const elapsed = end - start;

        console.log(`escapeArgument with escaped input time: ${elapsed.toFixed(2)}ms`);

        expect(result).to.be.a('string');
        expect(elapsed).to.be.lessThan(30000);
    });

    it('should return an empty string when passed empty input', () => {
        const result = escapeArgument('', true);

        expect(result).to.be('""'); // Proper escaped empty
    });
});
