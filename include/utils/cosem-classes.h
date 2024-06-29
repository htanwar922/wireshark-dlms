
/* Structure with the names of a DLMS/COSEM class */
struct dlms_cosem_class {
    const char *name;
    const char *attributes[18]; /* index 0 is attribute 2 (attribute 1 is always "logical_name") */
    const char *methods[11]; /* index 0 is method 1 */
};

const char *
dlms_get_attribute_name(const dlms_cosem_class *c, int attribute_id);

const char *
dlms_get_method_name(const dlms_cosem_class *c, int method_id);

/* Get the DLMS/COSEM class with the specified class_id */
const dlms_cosem_class *
dlms_get_class(int class_id);
