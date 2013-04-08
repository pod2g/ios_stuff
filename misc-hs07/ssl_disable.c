#include <Security/Security.h>

OSStatus new_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
	*result = kSecTrustResultProceed;
	return errSecSuccess;
}

const struct {void *n; void *o;} interposers[] __attribute((section("__DATA, __interpose"))) = {
    { (void *)new_SecTrustEvaluate, (void *)SecTrustEvaluate }
};