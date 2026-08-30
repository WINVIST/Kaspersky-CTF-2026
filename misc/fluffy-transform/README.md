# Fluffy Transform

**Категория:** Misc  
**Стоимость:** 128

> A damaged research recorder captured three voices sharing one throat. One is
> smooth, one has sharp corners, and one keeps changing direction. Something is
> moving inside the recording. It is not only where it goes, but when it chooses
> to move.

Дан один файл `challenge.wav`: mono PCM16, 48 kHz, примерно 21 секунда.

## Разбор

Сначала я построил обычный спектр. Ничего похожего на текст на спектрограмме не
было, зато нашлись три очень заметные несущие:

```text
997 Hz
2203 Hz
4211 Hz
```

У 2203 Hz также видны нечётные гармоники `6609, 11015, 15421, 19827`, а у
4211 Hz — `12633, 21055`. Тут подсказка стала почти прямой:

- 997 Hz — синус, гладкая волна;
- 2203 Hz — меандр с острыми углами;
- 4211 Hz — треугольная волна, которая постоянно меняет направление.

Частоты и фазы почти не меняются. Меняется именно амплитуда, поэтому я разбил
запись на окна по 25 мс и для каждой несущей подобрал коэффициенты синуса и
косинуса:

```python
A = np.column_stack([
    np.cos(2*np.pi*f*t),
    np.sin(2*np.pi*f*t),
])
c, s = np.linalg.lstsq(A, chunk, rcond=None)[0]
amplitude = np.hypot(c, s)
```

Три получившиеся огибающие можно считать координатами `X`, `Y`, `Z`. Если
нарисовать первые две как `plt.plot(X, Y)`, получается контур кота. Это объясняет
`Fluffy` в названии, но флага на картинке ещё нет.

Оставшаяся часть подсказки — *when it chooses to move*. Я нормализовал все три
координаты и посчитал расстояние между соседними точками:

```python
xyz = (xyz - xyz.min(0)) / np.ptp(xyz, axis=0)
speed = np.linalg.norm(np.diff(xyz, axis=0), axis=1)
moving = speed > 0.01
```

Получились очень ровные интервалы движения и остановки:

```text
движение  0.10 s  -> .
движение  0.25 s  -> -
пауза     0.05 s  -> внутри символа
пауза     0.20 s  -> следующий символ
```

То есть траектория передаёт обычную азбуку Морзе:

```text
.--. ....- .-- ... ..--.- .---- -. ..--.- - .... ...--
..--.- ... .--. ...-- -.-. - .-. ..- --
```

`..--.-` — это `_`. После декодирования получается:

```text
P4WS_1N_TH3_SP3CTRUM
```

Полный декодер лежит в [`solve.py`](solve.py):

```bash
python solve.py challenge.wav
```

## Флаг

```text
kaspersky{P4WS_1N_TH3_SP3CTRUM}
```

