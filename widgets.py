import math
from PyQt6.QtWidgets import QPushButton
from PyQt6.QtGui import QPainter, QColor, QPolygonF
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPointF
from appcore import log_exception


class Worker(QThread):
    """Поток для фоновых операций VPN, чтобы не блокировать GUI."""
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            self.fn(*self.args, **self.kwargs)
        except Exception as e:
            log_exception("Worker crashed")
            self.error.emit(str(e))
        finally:
            self.finished.emit()


class GearButton(QPushButton):
    """Круглая кнопка с нарисованной шестерёнкой (без emoji)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setText("")

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2
        outer = radius * 0.46
        inner = radius * 0.31
        hole = radius * 0.13
        teeth = 8

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#333"))

        points = []
        for i in range(teeth * 2):
            angle = i * 3.14159265 / teeth
            r = outer if i % 2 == 0 else inner
            points.append((cx + r * math.cos(angle),
                           cy + r * math.sin(angle)))

        polygon = QPolygonF([QPointF(x, y) for x, y in points])
        painter.drawPolygon(polygon)
        painter.drawEllipse(QPointF(cx, cy), hole, hole)
        painter.end()
