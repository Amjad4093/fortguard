package com.example.fortguarddemo

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.view.View

/** Colours shared by every screen: the same navy, teal and three decision colours as the back office. */
object Brand {
    val BG = Color.rgb(7, 17, 31)
    val NAVY = Color.rgb(6, 14, 27)
    val DEEP = Color.rgb(18, 48, 90)
    val CARD = Color.rgb(13, 26, 44)
    val FIELD = Color.rgb(10, 22, 38)
    val LINE = Color.rgb(42, 59, 85)
    val INK = Color.rgb(242, 246, 251)
    val MUTED = Color.rgb(147, 164, 186)
    val ACCENT = Color.rgb(47, 211, 167)
    val ACCENT2 = Color.rgb(74, 168, 255)
    val ON_ACCENT = Color.rgb(4, 35, 26)
    val WARN = Color.rgb(255, 181, 71)
    val DANGER = Color.rgb(255, 107, 107)

    fun levelColor(level: String): Int = when (level) {
        "ALLOW" -> ACCENT
        "STEP_UP" -> WARN
        else -> DANGER
    }
}

/** The FortGuard shield with its tick, drawn to fit whatever size the view is given. */
class ShieldView(context: Context) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }
    private val outline = Path()
    private val tick = Path()

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        // The shape is defined on a 150 by 170 grid and scaled to the view.
        val s = minOf(w / 150f, h / 170f)
        val dx = (w - 150f * s) / 2f
        val dy = (h - 170f * s) / 2f
        outline.reset()
        outline.moveTo(dx + 75f * s, dy + 6f * s)
        outline.lineTo(dx + 138f * s, dy + 30f * s)
        outline.lineTo(dx + 138f * s, dy + 82f * s)
        outline.cubicTo(dx + 138f * s, dy + 122f * s, dx + 112f * s, dy + 150f * s, dx + 75f * s, dy + 164f * s)
        outline.cubicTo(dx + 38f * s, dy + 150f * s, dx + 12f * s, dy + 122f * s, dx + 12f * s, dy + 82f * s)
        outline.lineTo(dx + 12f * s, dy + 30f * s)
        outline.close()
        tick.reset()
        tick.moveTo(dx + 48f * s, dy + 86f * s)
        tick.lineTo(dx + 68f * s, dy + 106f * s)
        tick.lineTo(dx + 104f * s, dy + 66f * s)
        paint.strokeWidth = 11f * s
        paint.shader = LinearGradient(0f, 0f, w.toFloat(), h.toFloat(), Brand.ACCENT, Brand.ACCENT2, Shader.TileMode.CLAMP)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.drawPath(outline, paint)
        canvas.drawPath(tick, paint)
    }
}

/**
 * The 0 to 1000 risk score on a half dial: green for allow, amber for step-up, red for block.
 * The bands are the server's defaults (600 and 900); the decision itself always comes from the server.
 */
class GaugeView(context: Context) : View(context) {
    private val density = resources.displayMetrics.density
    private val band = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.BUTT }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL; color = Brand.INK }
    private val number = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER; typeface = Typeface.DEFAULT_BOLD }
    private val caption = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER; color = Brand.MUTED }
    private val oval = RectF()
    private val pointer = Path()
    private var shown = 0f
    private var animator: ValueAnimator? = null

    /** Sweeps the dial from zero to [score]. */
    fun show(score: Int) {
        animator?.cancel()
        animator = ValueAnimator.ofFloat(0f, score.coerceIn(0, 1000).toFloat()).apply {
            duration = 900
            addUpdateListener { a ->
                shown = a.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    override fun onDetachedFromWindow() {
        animator?.cancel()
        super.onDetachedFromWindow()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = resolveSize((240 * density).toInt(), widthMeasureSpec).coerceAtMost((280 * density).toInt())
        setMeasuredDimension(width, (width * 0.62f).toInt())
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val stroke = w * 0.065f
        val r = w * 0.36f
        val cx = w / 2f
        val cy = w * 0.52f
        oval.set(cx - r, cy - r, cx + r, cy + r)
        band.strokeWidth = stroke
        val gap = 1.5f
        val step = 180f * STEP_FROM / 1000f
        val block = 180f * BLOCK_FROM / 1000f
        band.color = Brand.ACCENT
        canvas.drawArc(oval, 180f, step - gap, false, band)
        band.color = Brand.WARN
        canvas.drawArc(oval, 180f + step + gap, block - step - 2 * gap, false, band)
        band.color = Brand.DANGER
        canvas.drawArc(oval, 180f + block + gap, 180f - block - gap, false, band)

        // A small marker outside the dial, pointing in at the current score.
        val tip = cy - r - stroke * 0.8f
        pointer.reset()
        pointer.moveTo(cx, tip)
        pointer.lineTo(cx - stroke * 0.5f, tip - stroke * 0.95f)
        pointer.lineTo(cx + stroke * 0.5f, tip - stroke * 0.95f)
        pointer.close()
        canvas.save()
        canvas.rotate(-90f + 180f * shown / 1000f, cx, cy)
        canvas.drawPath(pointer, fill)
        canvas.restore()

        number.textSize = w * 0.19f
        number.color = when {
            shown >= BLOCK_FROM -> Brand.DANGER
            shown >= STEP_FROM -> Brand.WARN
            else -> Brand.ACCENT
        }
        canvas.drawText(shown.toInt().toString(), cx, cy - w * 0.02f, number)
        caption.textSize = w * 0.05f
        canvas.drawText("risk score of 1000", cx, cy + w * 0.06f, caption)
    }

    private companion object {
        const val STEP_FROM = 600
        const val BLOCK_FROM = 900
    }
}

/** A round badge for a decision: a tick for allow, an exclamation mark for step-up, a cross for block. */
class BadgeView(context: Context, private val level: String) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        color = Brand.levelColor(level)
    }
    private val mark = Path()

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val s = minOf(width, height).toFloat()
        val left = (width - s) / 2f
        val top = (height - s) / 2f
        paint.strokeWidth = s * 0.07f
        canvas.drawCircle(left + s / 2f, top + s / 2f, s * 0.44f, paint)
        mark.reset()
        when (level) {
            "ALLOW" -> {
                mark.moveTo(left + s * 0.30f, top + s * 0.52f)
                mark.lineTo(left + s * 0.44f, top + s * 0.66f)
                mark.lineTo(left + s * 0.72f, top + s * 0.36f)
            }
            "STEP_UP" -> {
                mark.moveTo(left + s * 0.50f, top + s * 0.28f)
                mark.lineTo(left + s * 0.50f, top + s * 0.56f)
                mark.moveTo(left + s * 0.50f, top + s * 0.71f)
                mark.lineTo(left + s * 0.50f, top + s * 0.72f)
            }
            else -> {
                mark.moveTo(left + s * 0.34f, top + s * 0.34f)
                mark.lineTo(left + s * 0.66f, top + s * 0.66f)
                mark.moveTo(left + s * 0.66f, top + s * 0.34f)
                mark.lineTo(left + s * 0.34f, top + s * 0.66f)
            }
        }
        paint.strokeWidth = s * 0.09f
        canvas.drawPath(mark, paint)
    }
}
