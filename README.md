# ud_fastAPI
Спочатку зробив з допомогою самого nist api.
Щоб запустити, використати файл main_nist.py
АПІ ключ не обов'язково. Зробив через asyncio.lock
через те, що апішка дуже погано дає відповіді, щоб тільки
один запит оброблявся в один момент. Працює, але дуже зі скрипом,
і навіть незважаючи на додану мною затримку в 15 секунд
між запитами до ніста, часто видає помилку 503.
Самі запити до апі зробив в окремому файлі - nist_api_access.py.
Також, зробив вивід сторінки /info в html форматі. 

Файл main.py читає все з json. Парсинг json вивів в окремий файл - parse_cve_json.py

Також, зробив заготовки до додаткового завдання з еластіком, але вони поки незакінчені.