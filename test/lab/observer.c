/* Test fixture only. Compare freed pointer values with NULL without dereferencing them.
 * Observe the values visible to a chained SAPI deactivate callback. Never install in production. */
#include "php.h"
#include "SAPI.h"
#include <unistd.h>
static int (*previous_deactivate)(void);
static int observe_deactivate(void)
{
    const char *marker = (SG(request_info).auth_user == NULL &&
        SG(request_info).auth_password == NULL && SG(request_info).auth_digest == NULL &&
        SG(request_info).content_type_dup == NULL && SG(request_info).current_user == NULL)
        ? "HP_LAB_SAPI_SAFE=1\n" : "HP_LAB_SAPI_SAFE=0\n";
    (void) write(2, marker, strlen(marker));
    return previous_deactivate ? previous_deactivate() : SUCCESS;
}
static PHP_MINIT_FUNCTION(hp_lab_observer)
{
    previous_deactivate = sapi_module.deactivate;
    sapi_module.deactivate = observe_deactivate;
    return SUCCESS;
}
zend_module_entry hp_lab_observer_module_entry = {
    STANDARD_MODULE_HEADER, "hp_lab_observer", NULL, PHP_MINIT(hp_lab_observer), NULL,
    NULL, NULL, NULL, "test-only", STANDARD_MODULE_PROPERTIES
};
ZEND_GET_MODULE(hp_lab_observer)
