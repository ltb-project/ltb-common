<?php

require __DIR__ . '/../../vendor/autoload.php';
use PHPUnit\Framework\TestCase;

class MandatoryAttributesTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{
    private function getAttributesMap()
    {
        return array(
            'firstname' => array('attribute' => 'givenname', 'mandatory' => array('all')),
            'lastname' => array('attribute' => 'sn', 'mandatory' => array('create')),
            'fullname' => array('attribute' => 'cn', 'mandatory' => array('update')),
            'title' => array('attribute' => 'title'),
        );
    }

    public function testCreateRequiresMandatoryValues()
    {
        $missing = (new \Ltb\Attributes)->findMissingMandatoryAttributes(
            'create',
            $this->getAttributesMap(),
            array(
                'givenname' => array('Alice'),
                'cn' => 'Alice Doe',
            )
        );

        $this->assertSame(array('lastname'), $missing);
    }

    public function testCreateAcceptsMandatoryMacroValue()
    {
        $missing = (new \Ltb\Attributes)->findMissingMandatoryAttributes(
            'create',
            $this->getAttributesMap(),
            array(
                'givenname' => array('Alice'),
                'sn' => 'Doe',
            )
        );

        $this->assertSame(array(), $missing);
    }

    public function testUpdateChecksOnlyProposedMandatoryAttributes()
    {
        $missing = (new \Ltb\Attributes)->findMissingMandatoryAttributes(
            'update',
            $this->getAttributesMap(),
            array(
                'givenname' => array(),
                'cn' => array(),
            ),
            array('fullname')
        );

        $this->assertSame(array('fullname'), $missing);
    }

    public function testUpdateIgnoresMandatoryAttributesNotProposedForChange()
    {
        $missing = (new \Ltb\Attributes)->findMissingMandatoryAttributes(
            'update',
            $this->getAttributesMap(),
            array(
                'givenname' => array(),
                'cn' => array(),
            ),
            array('title')
        );

        $this->assertSame(array(), $missing);
    }
}
