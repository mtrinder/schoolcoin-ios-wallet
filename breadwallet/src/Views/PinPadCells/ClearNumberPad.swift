//
//  ClearNumberPad.swift
//  breadwallet
//
//  Created by Adrian Corscadden on 2017-03-16.
//  Copyright © 2017 breadwallet LLC. All rights reserved.
//

import UIKit

class ClearNumberPad : GenericPinPadCell {

    override func setAppearance() {

        if text == "0" {
            topLabel.isHidden = true
            centerLabel.isHidden = false
        } else {
            topLabel.isHidden = false
            centerLabel.isHidden = true
        }

        topLabel.textColor = UIColor.blue
        centerLabel.textColor = UIColor.blue
        sublabel.textColor = UIColor.blue

        if isHighlighted {
            backgroundColor = .transparentBlack
            topLabel.textColor = .black
            centerLabel.textColor = .black
            sublabel.textColor = .black
        } else {
            if text == "" || text == deleteKeyIdentifier {
                backgroundColor = .clear
                imageView.image = imageView.image?.withRenderingMode(.alwaysTemplate)
                imageView.tintColor = UIColor.blue
            } else {
                backgroundColor = .transparentWhite
            }
        }
    }

    override func setSublabel() {
        guard let text = self.text else { return }
        if sublabels[text] != nil {
            sublabel.text = sublabels[text]
        }
    }
}
