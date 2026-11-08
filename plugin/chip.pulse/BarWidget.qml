import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons as Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "chip.pulse"

  readonly property string home: Quickshell.env("HOME") || ""
  readonly property string reportPath: (Quickshell.env("XDG_STATE_HOME") || home + "/.local/state") + "/omarchy-pulse/latest_report.json"

  property int healthScore: -1
  property bool needsAttention: false

  Commons.Translations {
    id: strings
    directory: Qt.resolvedUrl("i18n")
  }

  function launchPulse() {
    if (root.bar) {
      root.bar.run(root.home + "/.local/bin/omarchy-pulse-launch")
    }
  }

  function runQuickScan() {
    if (root.bar) {
      root.bar.run(root.home + "/.local/bin/omarchy-pulse-scan")
    }
  }

  function parseReport(raw) {
    var text = String(raw || "").trim()
    if (text === "" || text.length > 524288) return
    try {
      var parsed = JSON.parse(text)
      if (parsed && typeof parsed === "object") {
        var s = Number(parsed.health_score)
        if (isFinite(s) && s >= 0 && s <= 100) {
          root.healthScore = Math.round(s)
          root.needsAttention = root.healthScore < 85
        }
      }
    } catch (e) {
      // Ignore transient partial writes
    }
  }

  FileView {
    id: reportView
    path: root.reportPath
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
    onLoaded: root.parseReport(text())
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "\udb81\udce6"
    active: root.needsAttention
    tooltipText: root.healthScore >= 0
      ? strings.t("tooltip.score").arg(Commons.I18n.formatNumber(root.healthScore, 0))
      : strings.t("tooltip.default")

    onPressed: function(b) {
      if (b === Qt.RightButton) root.runQuickScan()
      else root.launchPulse()
    }
  }
}
