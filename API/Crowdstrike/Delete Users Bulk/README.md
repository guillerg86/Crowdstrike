Este script recupera los usuarios del fichero usuarios_baja.txt, los busca en el Tenant y los elimina.

Por defecto hace una simulacion (no lo borrará). Para ejecutar el borrado se ha de pasar el parametro.

```
--action delete
```

## Parámetros

|Parámetro|Valor por defecto|Valores posibles|
|-|-|-|
|`--ssl-verify`|`True`|`True` / `False`: Permite indicar si es necesario verificar el SSL|
|`--debug`|`False`|`True` / `False`|
|`--action`|`simulate`|`simulate` / `delete`: Permite simular el borrado de usuarios|